"""Nivel 2: deduplicar alertas y agrupar las que forman parte de la misma intrusión.

Todo es determinista (sin LLM). Dos alertas van al mismo grupo si comparten una entidad
(usuario, equipo, IP, dominio, hash, cliente, identidad cloud o mensaje de correo) y están
cerca en el tiempo. Dos cautelas evitan fusionar medio dataset por ruido:

- Una entidad que aparece en demasiadas alertas (la web de la tienda, un dominio de
  newsletters) no es una pista: se ignora (`max_frecuencia`).
- `es_relevante` permite agrupar solo las alertas que merecen la pena (tras el triaje, las
  que no son falso positivo ni actividad autorizada). Sin ese filtro, el ruido de las
  reglas más ruidosas une todas las alertas de un mismo usuario o equipo.

Qué se hace con un grupo (severidad, escalado, ticket único) está en `src/policy.py`
(`decision_de_grupo`) y en `consolidar_grupo` de este módulo.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any

from src.evidencia import entidades, normalizar_alerta
from src.policy import SEVERIDADES, decision_de_grupo
from src.soc_client import a_fecha

MAX_FRECUENCIA = 12

# Cuánto pueden distar dos alertas para unirlas por cada tipo de entidad. Una cuenta o un
# equipo comprometido da señales durante semanas (p. ej. el acceso de un proveedor); una IP
# o un dominio de ataque, en cambio, se reutilizan por otras campañas y por casualidad.
VENTANA = {
    "usuarios": timedelta(days=30),
    "hosts": timedelta(days=30),
    "clientes": timedelta(days=30),
    "cloud": timedelta(days=30),
    "ips": timedelta(days=3),
    "dominios": timedelta(days=3),
    "ficheros": timedelta(days=3),
    "mensajes": timedelta(days=3),
    "sesiones_ia": timedelta(days=3),
}


def _momento(alerta: dict[str, Any]) -> datetime:
    return a_fecha(alerta.get("created_at", "")) or datetime.min.replace(tzinfo=UTC)


def _claves(alerta: dict[str, Any]) -> list[tuple[str, str]]:
    """Entidades de la alerta como (tipo, valor), con el mensaje de correo incluido."""
    claves = [(tipo, v) for tipo, valores in entidades(alerta).items() if tipo in VENTANA for v in valores]
    mensaje = (alerta.get("evidence") or {}).get("message_id")
    if isinstance(mensaje, str) and mensaje:
        claves.append(("mensajes", mensaje))
    return claves


def deduplicar(alertas: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    """Quita las alertas idénticas (misma regla, entidades y evidencia).

    Devuelve las únicas, en el mismo orden, y un diccionario `id conservado -> ids repetidos`.
    """
    vistas: dict[str, str] = {}
    unicas: list[dict[str, Any]] = []
    repetidas: dict[str, list[str]] = defaultdict(list)
    for a in alertas:
        clave = json.dumps([a.get("rule_id"), a.get("entities"), a.get("evidence")], sort_keys=True, default=str)
        if clave in vistas:
            repetidas[vistas[clave]].append(a.get("alert_id", ""))
        else:
            vistas[clave] = a.get("alert_id", "")
            unicas.append(a)
    return unicas, dict(repetidas)


def agrupar(
    alertas: list[dict[str, Any]],
    *,
    es_relevante: Callable[[dict[str, Any]], bool] | None = None,
    max_frecuencia: int = MAX_FRECUENCIA,
) -> list[dict[str, Any]]:
    """Agrupa alertas relacionadas. Solo devuelve grupos de 2 o más alertas.

    Cada grupo: `grupo_id`, `alert_ids` (por hora), `reglas`, `entidades` (las que unen),
    `desde` y `hasta`. Las alertas se normalizan por dentro; las originales no se tocan.
    """
    candidatas = [normalizar_alerta(a) for a in alertas if es_relevante is None or es_relevante(a)]
    por_id = {a["alert_id"]: a for a in candidatas if a.get("alert_id")}
    padre = {i: i for i in por_id}

    def raiz(x: str) -> str:
        while padre[x] != x:
            padre[x] = padre[padre[x]]
            x = padre[x]
        return x

    por_entidad: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for a in por_id.values():
        for clave in set(_claves(a)):
            por_entidad[clave].append(a)

    uniones: dict[tuple[str, str], set[str]] = defaultdict(set)
    for (tipo, valor), lista in por_entidad.items():
        if len(lista) < 2 or len(lista) > max_frecuencia:
            continue
        lista.sort(key=_momento)
        for anterior, siguiente in pairwise(lista):
            if _momento(siguiente) - _momento(anterior) <= VENTANA[tipo]:
                padre[raiz(siguiente["alert_id"])] = raiz(anterior["alert_id"])
                uniones[(tipo, valor)].update((anterior["alert_id"], siguiente["alert_id"]))

    miembros: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for i, a in por_id.items():
        miembros[raiz(i)].append(a)

    grupos = []
    for lista in miembros.values():
        if len(lista) < 2:
            continue
        lista.sort(key=_momento)
        ids = {a["alert_id"] for a in lista}
        grupos.append({
            "grupo_id": f"GRP-{lista[0]['alert_id'].removeprefix('ALR-')}",
            "alert_ids": [a["alert_id"] for a in lista],
            "reglas": sorted({a.get("rule_id", "") for a in lista}),
            "entidades": [f"{tipo}: {valor}" for (tipo, valor), u in sorted(uniones.items()) if u <= ids],
            "desde": lista[0].get("created_at", ""),
            "hasta": lista[-1].get("created_at", ""),
        })
    return sorted(grupos, key=lambda g: g["desde"])


# --- Un único ticket por grupo ------------------------------------------------------------


def _sin_repetidos(elementos: list[dict[str, Any]], *campos: str) -> list[dict[str, Any]]:
    vistos: set[tuple] = set()
    salida = []
    for e in elementos:
        clave = tuple(str(e.get(c)) for c in campos)
        if clave not in vistos:
            vistos.add(clave)
            salida.append(e)
    return salida


PATRON_OBJETIVO = re.compile(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[\w.-]+@[\w.-]+\.\w+|[\w-]+(?:\.[\w-]+)+|s-[a-z0-9]+|eml-\d+)\b")


def _acciones_unicas(acciones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Quita acciones repetidas: cada alerta del grupo propone las suyas y suelen coincidir.

    Dos acciones iguales sobre el mismo objetivo (misma IP, cuenta, dominio o correo, aunque el
    modelo lo escriba distinto) se cuentan una vez. Si no se reconoce el objetivo, vale el texto.
    """
    vistas: list[tuple[str, set[str]]] = []
    salida = []
    for a in acciones:
        objetivo = a["target"].lower()
        claves = set(PATRON_OBJETIVO.findall(objetivo)) or {objetivo}
        if any(nombre == a["action"] and claves & otras for nombre, otras in vistas):
            continue
        vistas.append((a["action"], claves))
        salida.append(a)
    return salida


def consolidar_grupo(grupo: dict[str, Any], resultados: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """Une los tickets de las alertas de un grupo en uno solo (el que ve la persona).

    `resultados` es `id de alerta -> resultado de triar()`. Se ignoran las alertas sin ticket
    (con error o sin triar). Devuelve None si quedan menos de 2.
    """
    miembros = [(i, resultados[i]) for i in grupo["alert_ids"] if (resultados.get(i) or {}).get("ticket")]
    if len(miembros) < 2:
        return None
    tickets = [r["ticket"] for _, r in miembros]
    politicas = [r["politica"] for _, r in miembros]
    reglas = set(grupo["reglas"])
    decision = decision_de_grupo(
        [p["severidad_final"] for p in politicas],
        [m for p in politicas for m in p["motivos_escalado"]],
        reglas,
    )
    # La alerta principal es la más grave (a igualdad, la primera en el tiempo).
    principal = max(tickets, key=lambda t: SEVERIDADES.index(t["severity"]))
    ids = [i for i, _ in miembros]
    severidad = decision["severidad"]
    return {
        **principal,
        "ticket_id": f"TKT-{grupo['grupo_id']}",
        "alert_ids": ids,
        "title": f"{principal['title']} (+{len(ids) - 1} alertas relacionadas)",
        "verdict": principal["verdict"],
        "confidence": min(t["confidence"] for t in tickets),
        "severity": severidad,
        "severity_rationale": (
            f"Mayor severidad de las {len(ids)} alertas del grupo ({severidad}); "
            f"cada una ya incluye su ajuste ±1. {principal['severity_rationale']}"
        ),
        "summary": f"Intrusión formada por {len(ids)} alertas ({', '.join(sorted(reglas))}) "
                   f"del {grupo['desde'][:10]} al {grupo['hasta'][:10]}. Alerta principal: {principal['summary']}",
        "evidence": _sin_repetidos([e for t in tickets for e in t["evidence"]], "source", "event_id", "finding"),
        "enrichment": _sin_repetidos([e for t in tickets for e in t["enrichment"]], "indicator", "source"),
        "mitre": list(dict.fromkeys(m for t in tickets for m in t["mitre"])),
        "recommended_actions": _acciones_unicas([a for t in tickets for a in t["recommended_actions"]]),
        "executed_actions": [],
        "affected": {
            clave: list(dict.fromkeys(v for t in tickets for v in t["affected"].get(clave, [])))
            for clave in {c for t in tickets for c in t["affected"]}
        },
        "escalation": {
            "escalate": True,
            "to": decision["sla"]["escalado"],
            "reason": "; ".join(decision["motivos_escalado"]),
        },
        "open_questions": list(dict.fromkeys(q for t in tickets for q in t["open_questions"])),
        "triage_seconds": sum(t["triage_seconds"] for t in tickets),
        "decision": "escalar",
        "sla": decision["sla"],
        "grupo": {k: grupo[k] for k in ("grupo_id", "reglas", "entidades", "desde", "hasta")},
    }


# --- Agrupar lo ya triado ---------------------------------------------------------------------

VEREDICTOS_RELEVANTES = {"true_positive", "needs_more_info"}


def agrupar_resultados(resultados: dict[str, dict[str, Any]], alertas: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Grupos de las alertas ya triadas, cada uno con su ticket único (`ticket`).

    Solo cuentan las alertas que siguen siendo sospechosas tras el triaje (true_positive o
    needs_more_info): un falso positivo o una actividad autorizada no forma parte de una
    intrusión aunque comparta usuario o equipo con ella. `alertas` es `id -> alerta completa`.
    """
    relevantes = [
        alertas[i] for i, r in resultados.items()
        if i in alertas and (r.get("politica") or {}).get("veredicto") in VEREDICTOS_RELEVANTES
    ]
    salida = []
    for grupo in agrupar(relevantes):
        ticket = consolidar_grupo(grupo, resultados)
        if ticket:
            salida.append({**grupo, "severidad": ticket["severity"], "ticket": ticket})
    return salida
