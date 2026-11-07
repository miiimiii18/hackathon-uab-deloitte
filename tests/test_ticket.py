"""Tests de src/ticket.py: el ticket cumple el esquema oficial de Deloitte (sin red)."""

from src.llm import AnalisisLLM
from src.policy import aplicar_politica
from src.ticket import construir_ticket, enriquecimiento, tipo_indicador, validar_ticket

SENALES = {
    "ejecucion_o_acceso_confirmado": False,
    "identidad_vip_o_privilegiada": False,
    "datos_personales_o_pagos": False,
    "bloqueado_sin_actividad_posterior": False,
    "actividad_autorizada": False,
    "referencia_autorizacion": "",
}

ALERTA = {
    "alert_id": "ALR-20261009-011791",
    "severity": "high",
    "source_product": "EDR",
    "rule_id": "UC-EDR-001",
    "mitre": {"technique_id": "T1204.002"},
    "entities": {"customers": [{"customer_id": "C1"}]},
}

EVIDENCIA = {
    "activos": {"WS-BCN-1770": {"type": "Portátil", "criticality": "Media", "business_service": "Puesto de trabajo"}},
    "usuarios": {"marta.puig@tarvia.example": {"department": "Compras"}},
    "inteligencia": [
        {"indicador": "aplihartom.com", "estado": "malicious",
         "tip": {"reputation": "malicious", "malware_family": "Latrodectus", "confidence": 85}},
        {"indicador": "198.18.12.3", "estado": "unknown", "geo": {"as_org": "Hosting", "country": "NL", "is_hosting": "True"}},
    ],
    "sandbox": {"a" * 64: {"verdict": "malicious", "score": 96, "malware_family": "Latrodectus"}, "b" * 64: "Sin informe"},
}


def resultado(verdict="true_positive", acciones=(), alerta=ALERTA, **senales):
    analisis = AnalisisLLM(
        title="Latrodectus en un portátil", verdict=verdict, confidence=0.97, summary="Resumen para el N2.",
        evidence=[{"source": "edr_events", "event_id": "EDR-1", "finding": "DLL cargada"}],
        mitre=["T1059.007"], senales={**SENALES, **senales}, acciones_sugeridas=list(acciones),
        escalar_sugerido=False, motivo_escalado="", open_questions=["¿Hay más equipos afectados?"],
    )
    llm = {"analisis": analisis.model_dump(), "modelo": "ornith"}
    politica = aplicar_politica(alerta, EVIDENCIA, analisis).model_dump()
    return construir_ticket(alerta, EVIDENCIA, llm, politica, segundos=34.6)


def test_ticket_de_incidente_cumple_el_esquema_y_escala():
    acciones = [{"action": "isolate_host", "target": "WS-BCN-1770", "justification": "contener"}]
    t = resultado(acciones=acciones, ejecucion_o_acceso_confirmado=True)
    assert validar_ticket(t) == []
    assert t["ticket_id"] == "TKT-20261009-011791" and t["alert_ids"] == ["ALR-20261009-011791"]
    assert t["severity"] == "critical" and t["decision"] == "escalar"
    assert t["escalation"] == {"escalate": True, "to": "Inmediato a N2 de guardia por teléfono",
                               "reason": "true_positive de severidad critical; ejecución o acceso confirmado"}
    assert t["recommended_actions"][0]["aprobador"] == "N2"
    assert t["mitre"] == ["T1059.007", "T1204.002"]  # los del LLM + el de la alerta
    assert t["triage_seconds"] == 35


def test_afectados_salen_de_la_evidencia():
    t = resultado()
    assert t["affected"] == {"users": ["marta.puig@tarvia.example"], "hosts": ["WS-BCN-1770"],
                             "business_services": ["Puesto de trabajo"], "customers": ["C1"]}


def test_falso_positivo_se_cierra_con_accion_close():
    t = resultado("false_positive")
    assert validar_ticket(t) == []
    assert t["severity"] == "informational"
    assert [a["action"] for a in t["recommended_actions"]] == ["close"]
    assert t["escalation"] == {"escalate": False, "to": "", "reason": ""}


def test_needs_more_info_de_severidad_baja_pide_revision_humana():
    t = resultado("needs_more_info", alerta={**ALERTA, "severity": "low"})
    assert validar_ticket(t) == []
    assert t["decision"] == "revisar"
    assert t["recommended_actions"][-1]["action"] == "human_review"
    assert "¿Hay más equipos afectados?" in t["open_questions"]


def test_needs_more_info_de_severidad_alta_se_escala():
    t = resultado("needs_more_info")  # regla high × Media = high
    assert t["decision"] == "escalar" and "no se puede descartar" in t["escalation"]["reason"]


def test_el_veredicto_del_ticket_es_el_verificado_por_la_politica():
    t = resultado("benign_true_positive", referencia_autorizacion="porque es normal")
    assert t["verdict"] == "false_positive" and t["veredicto_llm"] == "benign_true_positive"
    assert any("autorización verificable" in q for q in t["open_questions"])


def test_enriquecimiento_una_entrada_por_fuente():
    filas = enriquecimiento(EVIDENCIA)
    fuentes = [(f["indicator"][:12], f["source"]) for f in filas]
    assert ("aplihartom.c", "ti_feed") in fuentes
    assert ("198.18.12.3", "ti_feed") in fuentes and ("198.18.12.3", "geoip_asn") in fuentes
    desconocido = next(f for f in filas if f["indicator"] == "198.18.12.3" and f["source"] == "ti_feed")
    assert "desconocido, no limpio" in desconocido["result"]
    assert sum(1 for f in filas if f["source"] == "sandbox") == 2


def test_tipos_de_indicador():
    assert tipo_indicador("10.0.0.1") == "ip"
    assert tipo_indicador("a" * 64) == "sha256"
    assert tipo_indicador("evil.example") == "domain"


def test_el_validador_detecta_tickets_mal_formados():
    t = resultado()
    t["verdict"] = "quizas"
    del t["summary"]
    errores = validar_ticket(t)
    assert any("verdict" in e for e in errores) and any("summary" in e for e in errores)
