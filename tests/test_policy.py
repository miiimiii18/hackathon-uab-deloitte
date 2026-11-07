"""Tests de src/policy.py: la política del SOC en código (sin LLM ni API)."""

import pytest

from src.llm import AnalisisLLM
from src.policy import (
    CRITICIDADES,
    MATRIZ,
    aplicar_politica,
    criticidad_afectada,
    permisos_accion,
    verificar_autorizacion,
)


def analisis(verdict="true_positive", acciones=(), escalar=False, **senales) -> AnalisisLLM:
    base = {
        "ejecucion_o_acceso_confirmado": False,
        "identidad_vip_o_privilegiada": False,
        "datos_personales_o_pagos": False,
        "bloqueado_sin_actividad_posterior": False,
        "actividad_autorizada": False,
        "referencia_autorizacion": "",
    }
    return AnalisisLLM(
        title="t", verdict=verdict, confidence=0.9, summary="s", evidence=[], mitre=[],
        senales={**base, **senales}, acciones_sugeridas=list(acciones),
        escalar_sugerido=escalar, motivo_escalado="", open_questions=[],
    )


PORTATIL = {"WS-BCN-1": {"type": "Portátil", "criticality": "Media", "zone": "HQ-USERS"}}
SERVIDOR_CRITICO = {"SQL-CRM01": {"type": "Base de datos", "criticality": "Crítica", "zone": "DC-SERVERS",
                                  "business_service": "CRM y datos de clientes"}}


def alerta(severity="medium", producto="EDR", rule_id="UC-EDR-002"):
    return {"alert_id": "ALR-1", "severity": severity, "source_product": producto, "rule_id": rule_id}


# --- Matriz y ajustes ------------------------------------------------------------------------


def test_la_matriz_es_la_de_la_politica():
    # Algunas celdas de politica_soc.md, comprobadas a mano.
    assert MATRIZ["low"][CRITICIDADES.index("Crítica")] == "medium"
    assert MATRIZ["medium"][CRITICIDADES.index("Baja")] == "low"
    assert MATRIZ["high"][CRITICIDADES.index("Crítica")] == "critical"
    assert MATRIZ["critical"][CRITICIDADES.index("Baja")] == "high"
    assert MATRIZ["informational"][CRITICIDADES.index("Alta")] == "low"


def test_true_positive_sin_ajustes():
    d = aplicar_politica(alerta("medium"), {"activos": PORTATIL}, analisis())
    assert (d.severidad_base, d.ajuste, d.severidad_final) == ("medium", 0, "medium")
    assert d.decision == "cerrar"


def test_varios_motivos_para_subir_cuentan_como_un_solo_nivel():
    a = analisis(ejecucion_o_acceso_confirmado=True, datos_personales_o_pagos=True)
    d = aplicar_politica(alerta("medium"), {"activos": PORTATIL}, a)
    assert d.ajuste == 1 and d.severidad_final == "high"
    assert len(d.motivos_ajuste) == 2


def test_bloqueado_baja_un_nivel():
    d = aplicar_politica(alerta("low", "WAF", "UC-WEB-001"), {}, analisis(bloqueado_sin_actividad_posterior=True))
    # low × Crítica (tienda online) = medium; −1 por bloqueado = low
    assert (d.criticidad, d.severidad_base, d.severidad_final) == ("Crítica", "medium", "low")


def test_subir_y_bajar_a_la_vez_se_compensan():
    a = analisis(ejecucion_o_acceso_confirmado=True, bloqueado_sin_actividad_posterior=True)
    d = aplicar_politica(alerta("medium"), {"activos": PORTATIL}, a)
    assert d.ajuste == 0 and d.severidad_final == "medium"


def test_la_severidad_no_pasa_de_critical():
    d = aplicar_politica(alerta("critical"), {"activos": SERVIDOR_CRITICO}, analisis(ejecucion_o_acceso_confirmado=True))
    assert d.severidad_final == "critical"


def test_identidad_privilegiada_se_toma_del_directorio_no_del_llm():
    ev = {"activos": PORTATIL, "usuarios": {"adm.joan@tarvia.example": {"privileged": "True", "vip": "False"}}}
    d = aplicar_politica(alerta("medium"), ev, analisis())
    assert d.ajuste == 1 and "adm.joan@tarvia.example" in d.motivos_ajuste[0]


# --- Criticidad -------------------------------------------------------------------------------


def test_criticidad_del_activo_mas_critico():
    c, origen = criticidad_afectada(alerta(), {"activos": {**PORTATIL, **SERVIDOR_CRITICO}})
    assert c == "Crítica" and "SQL-CRM01" in origen


def test_activo_desconocido_asume_media_y_lo_dice():
    c, origen = criticidad_afectada(alerta(), {"activos": {"X": "DESCONOCIDO: no aparece en la CMDB"}})
    assert c == "Media" and "se asume" in origen


# --- Veredicto y autorizaciones ----------------------------------------------------------------


def test_btp_sin_autorizacion_verificable_pasa_a_falso_positivo():
    a = analisis("benign_true_positive", actividad_autorizada=True, referencia_autorizacion="SCCM es una herramienta autorizada")
    d = aplicar_politica(alerta("medium"), {"activos": PORTATIL}, a)
    assert d.veredicto == "false_positive" and d.veredicto_llm == "benign_true_positive"
    assert d.severidad_final == "informational"
    assert any("autorización verificable" in x for x in d.avisos)


def test_btp_con_cambio_de_la_evidencia_se_mantiene():
    ev = {"activos": PORTATIL, "cambios_aprobados": [{"id": "CHG-2026-1049", "titulo": "Escaneo semanal"}]}
    a = analisis("benign_true_positive", referencia_autorizacion="Cambio CHG-2026-1049")
    d = aplicar_politica(alerta("high"), ev, a)
    assert d.veredicto == "benign_true_positive" and "CHG-2026-1049" in d.autorizacion
    assert d.severidad_final == "low"  # matriz high, pero autorizado → low


def test_un_cambio_inventado_no_vale():
    assert verificar_autorizacion("CHG-2026-9999", {"cambios_aprobados": [{"id": "CHG-2026-1049"}]}) == ""


def test_reglas_internas_de_tarvia_valen_como_autorizacion():
    assert "Pentest" in verificar_autorizacion("Pentest externo contratado", {})
    assert "gestoría" in verificar_autorizacion("Envío de nóminas a la Gestoría Pons", {})


# --- Escalado ----------------------------------------------------------------------------------


def test_tp_high_se_escala():
    d = aplicar_politica(alerta("high"), {"activos": PORTATIL}, analisis())
    assert d.decision == "escalar" and d.sla["escalado"] == "A N2 en la misma jornada"


def test_fraude_se_escala_aunque_sea_low():
    d = aplicar_politica(alerta("low", "EMAIL_GW", "UC-EML-004"), {"activos": PORTATIL}, analisis())
    assert d.decision == "escalar" and "fraude" in d.motivos_escalado[0]


def test_falso_positivo_se_cierra_y_descarta_acciones():
    acc = [{"action": "isolate_host", "target": "WS-BCN-1", "justification": "x"}]
    d = aplicar_politica(alerta("high"), {"activos": PORTATIL}, analisis("false_positive", acciones=acc))
    assert d.decision == "cerrar" and d.acciones == []
    assert any("descartan" in x for x in d.avisos)


def test_needs_more_info_se_revisa():
    d = aplicar_politica(alerta("low"), {"activos": PORTATIL}, analisis("needs_more_info"))
    assert d.decision == "revisar"


# --- Contención --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("accion", "target", "activos", "aprobador", "permitida"),
    [
        ("purge_email", "<msg@x>", {}, "—", True),
        ("block_ioc", "evil.example", {}, "—", True),
        ("block_ioc", "mega.nz", {}, "N2", True),
        ("isolate_host", "WS-BCN-1", PORTATIL, "N2", True),
        ("isolate_host", "POS-T01", {"POS-T01": {"type": "TPV", "zone": "STORES"}}, "N2 + negocio", True),
        ("isolate_host", "SQL-CRM01", SERVIDOR_CRITICO, "N2 + responsable de «CRM y datos de clientes»", True),
        ("isolate_host", "PLC-01", {"PLC-01": {"type": "PLC", "zone": "LOGISTICS-OT"}}, "Responsable de Operaciones", False),
        ("disable_user", "svc_backup", {}, "N2", True),
        ("disable_access_key", "AKIA...", {}, "N2", True),
    ],
)
def test_permisos_de_contencion(accion, target, activos, aprobador, permitida):
    a = permisos_accion(accion, target, "porque sí", {"activos": activos})
    assert a.aprobador == aprobador and a.permitida is permitida
    assert a.requires_approval is (aprobador != "—")
