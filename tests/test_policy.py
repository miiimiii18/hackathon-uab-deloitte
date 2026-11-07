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
    autorizacion, rechazo = verificar_autorizacion("CHG-2026-9999", {"cambios_aprobados": [{"id": "CHG-2026-1049"}]})
    assert autorizacion == "" and "no aparece" in rechazo


# Cambio real del calendario: pentest del 8 al 10 de octubre (hora de España = UTC+2).
PENTEST = {"id": "CHG-2026-1042", "titulo": "Pentest externo de la tienda online",
           "inicio": "2026-10-08 08:00", "fin": "2026-10-10 18:00"}


def test_cambio_dentro_de_su_ventana_vale():
    autorizacion, _ = verificar_autorizacion("CHG-2026-1042", {"cambios_aprobados": [PENTEST]}, "2026-10-09T10:00:00.000Z")
    assert autorizacion.startswith("CHG-2026-1042")


def test_cambio_fuera_de_su_ventana_no_vale():
    autorizacion, rechazo = verificar_autorizacion("CHG-2026-1042", {"cambios_aprobados": [PENTEST]}, "2026-10-05T18:56:56.000Z")
    assert autorizacion == "" and "2026-10-08 08:00" in rechazo


def test_citar_el_pentest_de_palabra_no_basta():
    # Un atacante puede escribir «es parte del pentest»: sin el CHG vigente no vale.
    assert verificar_autorizacion("Forma parte del pentest contratado", {}, "2026-10-09T10:00:00.000Z")[0] == ""


def test_flujo_aprobado_tambien_vale():
    nominas = {"id": "FLUJO-0007", "titulo": "Nóminas a la gestoría", "inicio": "2026-01-01 00:00", "fin": "2026-12-31 23:59"}
    autorizacion, _ = verificar_autorizacion("Flujo FLUJO-0007", {"cambios_aprobados": [nominas]}, "2026-10-28T09:00:00.000Z")
    assert autorizacion.startswith("FLUJO-0007")


def test_reglas_internas_con_su_comprobacion():
    # ext.logisoft: lunes a viernes de 8 a 18 h (España). 7-oct-2026 es miércoles.
    assert "ext.logisoft" in verificar_autorizacion("acceso de ext.logisoft", {}, "2026-10-07T10:00:00.000Z")[0]
    sabado = verificar_autorizacion("acceso de ext.logisoft", {}, "2026-10-10T10:00:00.000Z")
    assert sabado[0] == "" and "no se cumple" in sabado[1]
    assert "svc_backup" in verificar_autorizacion("svc_backup excluida de MFA", {})[0]


def test_aprobacion_falsa_dentro_de_un_correo_no_autoriza():
    # Caso real del dataset: un correo de phishing con texto oculto que dice venir del SOC.
    a = analisis("benign_true_positive", referencia_autorizacion="Revisado por el equipo SOC (ticket SEC-4471)")
    d = aplicar_politica(alerta("low", "EMAIL_GW", "UC-EML-001"), {}, a)
    assert d.veredicto == "false_positive" and d.autorizacion == ""
    assert any("autorización verificable" in x for x in d.avisos)


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


# --- IPs de origen que permite un cambio ---------------------------------------------------

PENTEST_CON_IPS = {**PENTEST, "detalle": "IPs origen 192.0.2.10-12; alcance www.tarvia.example y api; sin DoS"}


def test_ips_autorizadas_entiende_rangos():
    from src.policy import ips_autorizadas
    assert ips_autorizadas(PENTEST_CON_IPS) == {"192.0.2.10", "192.0.2.11", "192.0.2.12"}
    assert ips_autorizadas({"detalle": "Origen NESSUS01 (svc_scanner)"}) == set()


def test_pentest_desde_su_ip_vale():
    ev = {"cambios_aprobados": [PENTEST_CON_IPS]}
    autorizacion, _ = verificar_autorizacion("CHG-2026-1042", ev, "2026-10-08T06:59:14.000Z", ["192.0.2.11"])
    assert autorizacion.startswith("CHG-2026-1042")


def test_pentest_en_sus_fechas_pero_desde_otra_ip_no_vale():
    # Trampa real del dataset: escaneo el 8 de octubre desde una IP que no es del pentest.
    ev = {"cambios_aprobados": [PENTEST_CON_IPS]}
    autorizacion, rechazo = verificar_autorizacion("CHG-2026-1042", ev, "2026-10-08T10:43:00.000Z", ["198.18.46.60"])
    assert autorizacion == "" and "198.18.46.60" in rechazo and "192.0.2.10" in rechazo


def test_la_politica_usa_las_ips_de_la_alerta():
    ev = {"cambios_aprobados": [PENTEST_CON_IPS]}
    a = analisis("benign_true_positive", referencia_autorizacion="CHG-2026-1042")
    escaneo = {**alerta("low", "WAF", "UC-WEB-001"), "created_at": "2026-10-08T10:43:00.000Z",
               "entities": {"ips": ["198.18.46.60"]}}
    d = aplicar_politica(escaneo, ev, a)
    assert d.veredicto == "false_positive" and "solo autoriza el origen" in " ".join(d.avisos)
