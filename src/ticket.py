"""Ticket de triaje N1 en el formato de Deloitte (ticket_salida.schema.json).

Junta lo que propone el LLM (título, resumen, evidencias, MITRE...) con lo que decide
la política en código (veredicto final, severidad, escalado, permisos) y la evidencia
reunida (afectados, enriquecimiento). Es el «contrato» que consume la interfaz.

Campos del esquema oficial + algunos extra para la UI (el esquema los permite):
`decision` (cerrar | escalar | revisar), `sla`, `veredicto_llm`, `modelo`.

El esquema es una copia de data/tarvia/01_contexto/ticket_salida.schema.json (repo de
Deloitte), guardada en src/esquemas/ para poder validar sin el dataset (p. ej., en el CI).
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from src.evidencia import es_ip
from src.policy import CRITICIDAD_POR_PRODUCTO

RUTA_ESQUEMA = Path(__file__).parent / "esquemas" / "ticket_salida.schema.json"
PATRON_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _unicos(valores: list[str]) -> list[str]:
    vistos: list[str] = []
    for v in valores:
        if v and v not in vistos:
            vistos.append(v)
    return vistos


def tipo_indicador(valor: str) -> str:
    if es_ip(valor):
        return "ip"
    if PATRON_SHA256.match(valor):
        return "sha256"
    return "domain"


# --- Partes del ticket -----------------------------------------------------------------------


def afectados(alerta: dict[str, Any], evidencia: dict[str, Any]) -> dict[str, list[str]]:
    entidades = alerta.get("entities") or {}
    activos = evidencia.get("activos") or {}
    servicios = [a.get("business_service", "") for a in activos.values() if isinstance(a, dict)]
    if not any(servicios) and alerta.get("source_product") in CRITICIDAD_POR_PRODUCTO:
        servicios = [CRITICIDAD_POR_PRODUCTO[alerta["source_product"]][1]]
    return {
        "users": _unicos(list((evidencia.get("usuarios") or {}).keys())),
        "hosts": _unicos(list(activos.keys())),
        "business_services": _unicos(servicios),
        "customers": _unicos([c.get("customer_id", "") for c in entidades.get("customers", [])]),
    }


def _resultado_tip(tip: dict[str, Any] | None, estado: str) -> str:
    if not tip:
        return "sin coincidencias en el TIP (desconocido, no limpio)"
    partes = [tip.get("reputation", estado)]
    if tip.get("malware_family"):
        partes.append(tip["malware_family"])
    if tip.get("confidence") is not None:
        partes.append(f"confianza {tip['confidence']}")
    if tip.get("tags"):
        partes.append(f"etiquetas: {tip['tags']}")
    return ", ".join(str(p) for p in partes)


def _resultado_geo(geo: dict[str, Any]) -> str:
    partes = [geo.get("as_org", ""), geo.get("city", ""), geo.get("country", "")]
    banderas = [n for n, campo in (("Tor", "is_tor"), ("VPN", "is_vpn_provider"), ("hosting", "is_hosting"),
                                   ("proxy residencial", "is_residential_proxy")) if str(geo.get(campo)) == "True"]
    return ", ".join(p for p in partes + banderas if p)


def enriquecimiento(evidencia: dict[str, Any]) -> list[dict[str, str]]:
    """Una entrada por indicador y fuente, como en el ticket de ejemplo de Deloitte."""
    filas: list[dict[str, str]] = []
    for i in evidencia.get("inteligencia") or []:
        ind = i.get("indicador", "")
        tipo = tipo_indicador(ind)
        filas.append({"indicator": ind, "type": tipo, "source": "ti_feed",
                      "result": _resultado_tip(i.get("tip"), i.get("estado", "unknown"))})
        if i.get("geo"):
            filas.append({"indicator": ind, "type": tipo, "source": "geoip_asn", "result": _resultado_geo(i["geo"])})
    for sha, informe in (evidencia.get("sandbox") or {}).items():
        if isinstance(informe, dict):
            resultado = ", ".join(str(x) for x in (informe.get("verdict"), f"puntuación {informe.get('score')}",
                                                    informe.get("malware_family")) if x)
        else:
            resultado = "sin informe de sandbox"
        filas.append({"indicator": sha, "type": "sha256", "source": "sandbox", "result": resultado})
    return filas


def acciones_recomendadas(politica: dict[str, Any]) -> list[dict[str, Any]]:
    acciones = [
        {
            "action": a["action"],
            "target": a["target"],
            "requires_approval": a["requires_approval"],
            "justification": a["justification"],
            # Extra para la UI: quién aprueba y si la política la permite.
            "aprobador": a["aprobador"],
            "permitida": a["permitida"],
            "nota": a.get("nota", ""),
        }
        for a in politica.get("acciones", [])
    ]
    if politica["decision"] == "revisar":
        acciones.append({"action": "human_review", "target": "ticket", "requires_approval": True,
                         "justification": "needs_more_info: un analista debe revisar las preguntas abiertas",
                         "aprobador": "N1", "permitida": True, "nota": ""})
    elif politica["decision"] == "cerrar" and not acciones:
        acciones.append({"action": "close", "target": "ticket", "requires_approval": False,
                         "justification": politica.get("razon_severidad", ""),
                         "aprobador": "—", "permitida": True, "nota": ""})
    return acciones


# --- Ticket completo ----------------------------------------------------------------------------


def construir_ticket(
    alerta: dict[str, Any],
    evidencia: dict[str, Any],
    llm: dict[str, Any],
    politica: dict[str, Any],
    segundos: float | None = None,
) -> dict[str, Any]:
    """Arma el ticket a partir de la evidencia, el resultado del LLM y la decisión de la política.

    `llm` y `politica` son los diccionarios que guarda src/triaje.py (`.model_dump()`).
    """
    a = llm["analisis"]
    alert_id = alerta.get("alert_id", "ALR-SIN-ID")
    mitre_alerta = (alerta.get("mitre") or {}).get("technique_id", "")
    escalar = politica["decision"] == "escalar"
    return {
        "ticket_id": f"TKT-{alert_id.removeprefix('ALR-')}",
        "alert_ids": [alert_id],
        "title": a["title"],
        "verdict": politica["veredicto"],  # el verificado por la política, no el del LLM
        "confidence": a["confidence"],
        "severity": politica["severidad_final"],
        "severity_rationale": f"{politica['razon_severidad']} {politica['origen_criticidad']}.",
        "affected": afectados(alerta, evidencia),
        "summary": a["summary"],
        "evidence": [{"source": e["source"], "event_id": e["event_id"], "finding": e["finding"]} for e in a["evidence"]],
        "enrichment": enriquecimiento(evidencia),
        "mitre": _unicos(list(a["mitre"]) + [mitre_alerta]),
        "recommended_actions": acciones_recomendadas(politica),
        "executed_actions": [],  # se llena cuando una persona aprueba y se ejecuta la contención
        "escalation": {
            "escalate": escalar,
            "to": politica["sla"]["escalado"] if escalar else "",
            "reason": "; ".join(politica["motivos_escalado"]) if escalar else "",
        },
        "open_questions": list(a["open_questions"]) + list(politica["avisos"]),
        "triage_seconds": round(segundos) if segundos is not None else 0,
        # --- Extra para la UI ---
        "decision": politica["decision"],
        "sla": politica["sla"],
        "veredicto_llm": politica["veredicto_llm"],
        "modelo": llm.get("modelo", ""),
    }


@cache
def _validador() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUTA_ESQUEMA.read_text(encoding="utf-8")))


def validar_ticket(ticket: dict[str, Any]) -> list[str]:
    """Errores del ticket frente al esquema oficial (lista vacía = válido)."""
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '(raíz)'}: {e.message}"
        for e in sorted(_validador().iter_errors(ticket), key=lambda e: list(e.absolute_path))
    ]
