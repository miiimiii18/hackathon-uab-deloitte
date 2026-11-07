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

import csv
import hashlib
import ipaddress
import json
import os
import re
from functools import cache
from pathlib import Path
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


# IDs del calendario de cambios: cambios (CHG-2026-1042) y flujos aprobados (FLUJO-0007).
PATRON_CAMBIO = re.compile(r"\b(?:CHG|FLUJO)-\d+(?:-\d+)?\b", re.IGNORECASE)


def cambios_citados(alerta: dict[str, Any]) -> list[str]:
    """IDs de cambios o flujos que aparecen en cualquier campo de la alerta."""
    texto = json.dumps(alerta, ensure_ascii=False)
    return _unicos([i.upper() for i in PATRON_CAMBIO.findall(texto)])


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


def _lista(valor: Any) -> list:
    if valor is None:
        return []
    return valor if isinstance(valor, list) else [valor]


RUTA_CATALOGO = Path(os.getenv("TARVIA_PATH", "data/tarvia")) / "01_contexto" / "catalogo_casos_de_uso.csv"
SEVERIDADES_REGLA = ("informational", "low", "medium", "high", "critical")
PREFIJO_MANUAL = "ALR-MANUAL-"  # ID que se pone a una alerta pegada sin alert_id


@cache
def catalogo() -> dict[str, dict[str, str]]:
    """Catálogo oficial de reglas (rule_id → nombre, severidad base, runbook). Vacío si no está el dataset."""
    if not RUTA_CATALOGO.exists():
        return {}
    with RUTA_CATALOGO.open(encoding="utf-8", newline="") as f:
        return {fila["rule_id"]: fila for fila in csv.DictReader(f) if fila.get("rule_id")}


def motivo_de_rechazo(alerta: Any) -> str | None:
    """Por qué no se puede triar una alerta pegada (None = se puede). Solo se exige algo que investigar."""
    if not isinstance(alerta, dict):
        return "no es un objeto JSON"
    if not any(alerta.get(c) for c in ("rule_id", "rule_name", "entities", "evidence")):
        return "no trae nada que investigar (ni rule_id, ni rule_name, ni entities, ni evidence)"
    return None


def completar_alerta(alerta: dict[str, Any]) -> dict[str, Any]:
    """Rellena lo que falta en una alerta pobre y anota cada cosa en `avisos_de_carga`.

    - Sin `alert_id`: uno estable a partir del contenido (`ALR-MANUAL-…`), así la misma alerta pegada
      dos veces tiene el mismo ID.
    - Con un `rule_id` del catálogo: nombre, severidad base y runbook de la regla si faltan.
    - Sin `created_at` no se inventa una hora (con la de hoy, la ventana de ±24 h caería fuera de
      los datos): se avisa de que los logs se buscan sin ventana temporal.
    """
    a = dict(alerta)
    # Los avisos se calculan siempre aquí: unos que vinieran en la alerta los habría escrito quien la
    # envía (quizá el atacante) y se enseñarían como si fueran del sistema.
    a.pop("avisos_de_carga", None)
    avisos: list[str] = []

    def avisar(texto: str) -> None:
        if texto not in avisos:
            avisos.append(texto)

    if not a.get("alert_id"):
        huella = hashlib.sha256(json.dumps(a, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:10].upper()
        a["alert_id"] = f"{PREFIJO_MANUAL}{huella}"
    if str(a["alert_id"]).startswith(PREFIJO_MANUAL):  # asignado aquí o por la web al pegarla
        avisar(f"La alerta no traía alert_id: se le asigna {a['alert_id']}.")
    regla = catalogo().get(str(a.get("rule_id") or ""))
    if regla:
        if not a.get("rule_name"):
            a["rule_name"] = regla["nombre"]
        if str(a.get("severity") or "").strip().lower() not in SEVERIDADES_REGLA and regla.get("severidad_base"):
            avisar(f"La alerta no traía una severidad válida: se usa la de la regla en el catálogo ({regla['severidad_base']}).")
            a["severity"] = regla["severidad_base"]
        if not a.get("runbook") and regla.get("runbook"):
            a["runbook"] = regla["runbook"]
            avisar(f"La alerta no traía runbook: se usa el de la regla en el catálogo ({regla['runbook']}).")
    elif a.get("rule_id"):
        avisar(f"La regla {a['rule_id']} no está en el catálogo: se revisan las fuentes de log por defecto.")
    if not a_fecha(str(a.get("created_at") or "")):
        avisar("La alerta no traía una hora válida (created_at): los logs se buscan sin ventana de ±24 h y las "
               "reglas que dependen de la hora no se pueden comprobar.")
    if not a.get("entities"):
        avisar("La alerta no trae entidades (equipos, usuarios, IPs...): hay poco que consultar y la confianza será baja.")
    if avisos:
        a["avisos_de_carga"] = avisos
    return a


def normalizar_alerta(alerta: dict[str, Any]) -> dict[str, Any]:
    """Devuelve una copia de la alerta con un formato predecible, para que nada se rompa.

    Las 10 alertas del domingo pueden venir de fuera del dataset y con campos raros:
    usuarios u hosts como texto en vez de objetos, valores None o números, listas que
    llegan como un solo valor, severidad en mayúsculas... Aquí se arregla todo eso UNA
    vez, al entrar, en vez de comprobarlo en cada sitio que lee la alerta.
    """
    a = dict(alerta) if isinstance(alerta, dict) else {}
    ent = a.get("entities") if isinstance(a.get("entities"), dict) else {}

    def objetos(valores: Any, clave: str) -> list[dict]:
        salida = []
        for v in _lista(valores):
            if isinstance(v, str) and v.strip():
                salida.append({clave: v.strip()})
            elif isinstance(v, dict):
                salida.append(v)
        return salida

    def textos(valores: Any) -> list[str]:
        return [v.strip() for v in _lista(valores) if isinstance(v, str) and v.strip()]

    normal = {
        "users": objetos(ent.get("users"), "upn"),
        "hosts": objetos(ent.get("hosts"), "hostname"),
        "ips": textos(ent.get("ips")),
        "domains": textos(ent.get("domains")),
        "urls": textos(ent.get("urls")),
        "files": [f for f in _lista(ent.get("files")) if isinstance(f, dict)],
        "customers": objetos(ent.get("customers"), "customer_id"),
        "processes": [p for p in _lista(ent.get("processes")) if isinstance(p, dict)],
    }
    if isinstance(ent.get("cloud"), dict):
        normal["cloud"] = ent["cloud"]
    if isinstance(ent.get("ai_session"), str):
        normal["ai_session"] = ent["ai_session"]
    a["entities"] = {k: v for k, v in normal.items() if v}
    a["evidence"] = a.get("evidence") if isinstance(a.get("evidence"), dict) else {}
    a["related_events"] = textos(a.get("related_events"))
    if isinstance(a.get("severity"), str):
        a["severity"] = a["severity"].strip().lower()
    return a


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
    # También por dominio: p. ej., el pentest (CHG-2026-1042) menciona www.tarvia.example.
    for termino in [upn.split("@")[0] for upn in e["usuarios"]] + e["hosts"] + e["ips"] + e["dominios"]:
        for c in cliente.cambios(termino):
            cambios[c.get("id", str(c))] = compactar(c)
    # Y los cambios que cita la propia alerta (p. ej., "change_ticket": "CHG-2026-1078"),
    # para poder comprobar si existen, qué cubren y si sus fechas encajan.
    for ident in cambios_citados(alerta):
        for c in cliente.cambios(ident):
            if str(c.get("id", "")).upper() == ident:
                cambios[ident] = compactar(c)
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
