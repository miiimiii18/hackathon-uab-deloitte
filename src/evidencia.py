"""Reúne la evidencia de una alerta consultando la API del SOC.

Es la parte «determinista» del triaje (ver CLAUDE.md): el código decide QUÉ se
consulta, siguiendo el runbook de la alerta, y el LLM solo razona sobre el resultado.
Lo que se reúne, en este orden:
1. Contexto de las entidades: activos (CMDB), usuarios (directorio + RRHH).
2. Inteligencia de los indicadores (TIP + GeoIP) y sandbox de los ficheros.
3. Cambios aprobados que mencionan a las entidades.
4. Los eventos que cita la alerta (`related_events`).
5. Otros eventos de las mismas entidades ±24 h en las fuentes del runbook
   (Deloitte avisa: la clave suele estar en eventos que la alerta NO cita).

El resultado se recorta para que quepa en el contexto del modelo local.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import urlparse

from src.soc_client import SocClient, a_fecha, ventana

# Fuentes de log que se revisan según el runbook de la alerta.
FUENTES_POR_RUNBOOK: dict[str, list[str]] = {
    "RB-01": ["email", "email_clicks", "proxy", "edr_events", "idp_signins"],  # phishing
    "RB-02": ["edr_events", "proxy", "dns", "firewall"],  # malware en el puesto
    "RB-03": ["idp_signins", "idp_audit", "vpn", "ad_events"],  # identidad
    "RB-04": ["dlp", "proxy", "edr_events", "email"],  # fuga de datos
    "RB-05": ["waf", "ecom_auth", "ecom_account"],  # tienda online y fraude
    "RB-06": ["cloudtrail"],  # cloud
    "RB-07": ["ai_gateway", "ecom_account"],  # asistente Vela
    "RB-08": ["firewall", "edr_events", "vpn"],  # logística y OT
    "RB-09": ["firewall", "dns", "proxy", "edr_events"],  # red
    "RB-10": ["cicd_builds", "cloudtrail", "proxy"],  # CI/CD
}
FUENTES_POR_DEFECTO = ["edr_events", "proxy", "idp_signins"]

MAX_TERMINOS = 4  # entidades distintas que se buscan en los logs
MAX_INDICADORES = 6
MAX_EVENTOS_RELACIONADOS = 10
# Tope de evidencia. Este texto (JSON en español) sale a ~2,8 caracteres por token,
# así que 14.000 caracteres ≈ 5.000 tokens. Con el prompt fijo (~5.000) y la alerta,
# cada petición ronda los 10.000 tokens: más evidencia = más lenta y más ruido.
MAX_CARACTERES = 14_000

# Solo las redes internas «de verdad». No se usa ip.is_private porque marca como
# privadas 198.18.0.0/15 o 203.0.113.0/24, que en este dataset hacen de IPs de internet.
REDES_INTERNAS = [ipaddress.ip_network(r) for r in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]

NOTA_DESCONOCIDO = "DESCONOCIDO: no aparece en {donde}. Es un dato, no un error (p. ej., equipo no gestionado o externo)."


def es_ip(texto: str) -> bool:
    try:
        ipaddress.ip_address(texto)
        return True
    except ValueError:
        return False


def es_ip_interna(texto: str) -> bool:
    return es_ip(texto) and any(ipaddress.ip_address(texto) in red for red in REDES_INTERNAS)


def _unicos(valores: list[str]) -> list[str]:
    vistos: list[str] = []
    for v in valores:
        if v and v not in vistos:
            vistos.append(v)
    return vistos


def _upn_valido(upn: Any) -> bool:
    # Algunas alertas traen marcadores como "(12 cuentas)" en vez de un usuario real.
    return isinstance(upn, str) and "@" in upn and not upn.startswith("(")


# --- Qué buscar ------------------------------------------------------------------------


def entidades(alerta: dict[str, Any]) -> dict[str, list[str]]:
    """Extrae de la alerta las entidades en listas simples y sin repetidos."""
    ent = alerta.get("entities") or {}
    hosts = [h.get("hostname", "") for h in ent.get("hosts", [])]
    ips_host = [h.get("ip", "") for h in ent.get("hosts", [])]
    urls = [u for u in ent.get("urls", []) if isinstance(u, str)]
    cloud = ent.get("cloud") or {}
    return {
        "usuarios": _unicos([u.get("upn", "") for u in ent.get("users", []) if _upn_valido(u.get("upn"))]),
        "hosts": _unicos(hosts),
        "ips": _unicos([i for i in ent.get("ips", []) + ips_host if es_ip(i)]),
        "dominios": _unicos(ent.get("domains", []) + [urlparse(u).hostname or "" for u in urls]),
        "ficheros": _unicos([f.get("sha256", "") for f in ent.get("files", [])]),
        "clientes": _unicos([c.get("customer_id", "") for c in ent.get("customers", [])]),
        "cloud": _unicos([cloud.get("identity", ""), cloud.get("bucket", "")]),
        "sesiones_ia": _unicos([ent["ai_session"]] if isinstance(ent.get("ai_session"), str) else []),
    }


def terminos_de_busqueda(e: dict[str, list[str]]) -> list[tuple[str, str]]:
    """Qué se busca en los logs, por orden de prioridad. Devuelve (tipo, término)."""
    terminos: list[tuple[str, str]] = []
    terminos += [("usuario", upn.split("@")[0]) for upn in e["usuarios"]]
    terminos += [("host", h) for h in e["hosts"]]
    terminos += [("ip", ip) for ip in e["ips"] if not es_ip_interna(ip) or not e["hosts"]]
    terminos += [("dominio", d) for d in e["dominios"]]
    terminos += [("cliente", c) for c in e["clientes"]]
    terminos += [("cloud", c) for c in e["cloud"]]
    terminos += [("sesion_ia", s) for s in e["sesiones_ia"]]
    return terminos[:MAX_TERMINOS]


# --- Formato de la evidencia -------------------------------------------------------------


def compactar(evento: Any) -> Any:
    """Quita campos vacíos para que la evidencia ocupe menos."""
    if isinstance(evento, dict):
        return {k: compactar(v) for k, v in evento.items() if v not in (None, "", [], {})}
    if isinstance(evento, list):
        return [compactar(v) for v in evento]
    return evento


def _mas_cercanos(eventos: list[dict], momento: str, n: int) -> list[dict]:
    """Los n eventos más cercanos en el tiempo a la alerta, ordenados cronológicamente."""
    centro = a_fecha(momento)
    if centro is None:
        return eventos[:n]

    def distancia(e: dict) -> float:
        t = a_fecha(e.get("timestamp", ""))
        return abs((t - centro).total_seconds()) if t else float("inf")

    elegidos = sorted(eventos, key=distancia)[:n]
    return sorted(elegidos, key=lambda e: e.get("timestamp", ""))


def estado_intel(tip: dict | None) -> str:
    """malicious | suspicious | clean | unknown. Sin entrada en el TIP = unknown, nunca clean."""
    reputacion = (tip or {}).get("reputation", "")
    return {"malicious": "malicious", "suspicious": "suspicious", "benign": "clean"}.get(reputacion, "unknown")


# --- Recogida ----------------------------------------------------------------------------


def reunir_evidencia(alerta: dict[str, Any], cliente: SocClient) -> dict[str, Any]:
    """Consulta la API y devuelve la evidencia de la alerta, lista para el LLM."""
    e = entidades(alerta)
    momento = alerta.get("created_at", "")
    desde, hasta = ventana(momento) if a_fecha(momento) else (None, None)
    ev: dict[str, Any] = {}

    # 1. Contexto de las entidades.
    ev["activos"] = {
        h: compactar(cliente.activo(h)) or NOTA_DESCONOCIDO.format(donde="la CMDB")
        for h in e["hosts"] + [ip for ip in e["ips"] if es_ip_interna(ip) and not e["hosts"]]
    }
    ev["usuarios"] = {
        upn: compactar(cliente.usuario(upn)) or NOTA_DESCONOCIDO.format(donde="el directorio")
        for upn in e["usuarios"]
    }

    # 2. Inteligencia de indicadores externos y sandbox.
    indicadores = [ip for ip in e["ips"] if not es_ip_interna(ip)] + e["dominios"] + e["ficheros"]
    ev["inteligencia"] = []
    for ind in indicadores[:MAX_INDICADORES]:
        r = cliente.intel(ind) or {}
        ev["inteligencia"].append(
            compactar({"indicador": ind, "estado": estado_intel(r.get("tip")), "tip": r.get("tip"), "geo": r.get("geo")})
        )
    ev["sandbox"] = {
        sha: compactar(cliente.sandbox(sha)) or "Sin informe: el fichero no se ha enviado a la sandbox."
        for sha in e["ficheros"]
    }

    # 3. Cambios aprobados y flujos que mencionan a las entidades.
    cambios: dict[str, dict] = {}
    for termino in [upn.split("@")[0] for upn in e["usuarios"]] + e["hosts"] + e["ips"]:
        for c in cliente.cambios(termino):
            cambios[c.get("id", str(c))] = compactar(c)
    ev["cambios_aprobados"] = list(cambios.values())

    # 4. Eventos que cita la alerta.
    citados = alerta.get("related_events", [])[:MAX_EVENTOS_RELACIONADOS]
    ev["eventos_citados_en_la_alerta"] = [
        compactar(cliente.evento(i, desde, hasta)) or {"event_id": i, "nota": "no encontrado en los logs ±24 h"}
        for i in citados
    ]

    # 5. Otros eventos de las mismas entidades ±24 h en las fuentes del runbook.
    fuentes = FUENTES_POR_RUNBOOK.get(alerta.get("runbook", ""), FUENTES_POR_DEFECTO)
    grupos = []
    for tipo, termino in terminos_de_busqueda(e):
        for fuente in fuentes:
            r = cliente.logs(fuente, termino, desde, hasta, subdominios=(tipo == "dominio"))
            eventos = [x for x in r["eventos"] if x.get("event_id") not in citados]
            grupos.append({"fuente": fuente, "busqueda": f"{tipo}={termino}", "total": len(eventos),
                           "truncado": r["truncado"], "eventos": eventos})

    ev["notas"] = [
        "Los eventos de contexto son de ±24 h alrededor de la alerta (horas en UTC).",
        "En los cambios aprobados, las horas no indican zona horaria.",
        "total = eventos encontrados; solo se muestran los más cercanos a la alerta.",
    ]
    return _recortar(ev, grupos, momento)


def _recortar(ev: dict[str, Any], grupos: list[dict], momento: str) -> dict[str, Any]:
    """Añade los eventos de contexto con el máximo de ejemplos que quepa en MAX_CARACTERES."""
    for n in (5, 3, 2, 1, 0):
        ev["contexto_logs"] = [
            {k: v for k, v in g.items() if k != "eventos"}
            | ({"muestra": [compactar(x) for x in _mas_cercanos(g["eventos"], momento, n)]} if n and g["eventos"] else {})
            for g in grupos
        ]
        if len(json.dumps(ev, ensure_ascii=False, separators=(",", ":"))) <= MAX_CARACTERES:
            break
    return ev
