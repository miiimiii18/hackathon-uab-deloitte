"""Tests de src/agrupar.py: deduplicar, agrupar y un único ticket por grupo (sin red)."""

from src.agrupar import agrupar, consolidar_grupo, deduplicar, posiciones_duplicadas
from src.ticket import validar_ticket
from tests.test_ticket import EVIDENCIA, resultado


def alerta(n, regla="UC-EDR-001", dia=9, hora=10, **entidades):
    return {
        "alert_id": f"ALR-202610{dia:02d}-{n:06d}",
        "created_at": f"2026-10-{dia:02d}T{hora:02d}:00:00.000Z",
        "rule_id": regla,
        "severity": "high",
        "source_product": "EDR",
        "entities": entidades,
        "evidence": {"n": n},
    }


def host(nombre):
    return {"hosts": [{"hostname": nombre, "ip": f"10.10.{sum(map(ord, nombre)) % 250}.5"}]}


def usuario(upn):
    return {"users": [{"upn": upn}]}


def test_deduplicar_quita_las_identicas_y_cuenta_las_repetidas():
    a = alerta(1, **host("PC1"))
    copia = {**a, "alert_id": "ALR-20261009-000002", "created_at": "2026-10-09T11:00:00.000Z"}
    otra = alerta(3, **host("PC1"))
    unicas, repetidas = deduplicar([a, copia, otra])
    assert [x["alert_id"] for x in unicas] == [a["alert_id"], otra["alert_id"]]
    assert repetidas == {a["alert_id"]: [copia["alert_id"]]}


def test_posiciones_duplicadas_apunta_a_la_primera_y_salta_las_desconocidas():
    a = alerta(1, **host("PC1"))
    copia = {**a, "alert_id": "ALR-20261009-000002"}
    otra = alerta(3, **host("PC2"))
    assert posiciones_duplicadas([a, None, otra, copia, dict(copia)]) == {3: 0, 4: 0}
    assert posiciones_duplicadas([None, None]) == {}


def test_dos_alertas_del_mismo_equipo_van_juntas_y_ordenadas_por_hora():
    tarde = alerta(2, "UC-NET-002", hora=15, **host("PC1"))
    pronto = alerta(1, "UC-EML-003", hora=9, **host("PC1"))
    ajena = alerta(3, "UC-EDR-003", **host("PC2"))
    grupos = agrupar([tarde, pronto, ajena])
    assert len(grupos) == 1
    g = grupos[0]
    assert g["alert_ids"] == [pronto["alert_id"], tarde["alert_id"]]
    assert g["reglas"] == ["UC-EML-003", "UC-NET-002"]
    assert "hosts: PC1" in g["entidades"] and g["grupo_id"] == "GRP-20261009-000001"


def test_una_alerta_sola_no_forma_grupo():
    assert agrupar([alerta(1, **host("PC1"))]) == []


def test_la_union_es_transitiva_a_traves_de_otra_entidad():
    a = alerta(1, **host("PC1"), **usuario("ana@tarvia.example"))
    b = alerta(2, **usuario("ana@tarvia.example"), ips=["198.51.100.7"])
    c = alerta(3, ips=["198.51.100.7"])
    assert len(agrupar([a, b, c])[0]["alert_ids"]) == 3


def test_una_entidad_demasiado_frecuente_no_une():
    ruido = [alerta(i, **host("WEB"), **usuario(f"u{i}@tarvia.example")) for i in range(1, 6)]
    assert agrupar(ruido, max_frecuencia=4) == []
    assert len(agrupar(ruido, max_frecuencia=5)) == 1


def test_la_ventana_depende_del_tipo_de_entidad():
    lejos_ip = [alerta(1, dia=5, ips=["198.51.100.7"]), alerta(2, dia=20, ips=["198.51.100.7"])]
    assert agrupar(lejos_ip) == []  # una IP reutilizada semanas después no es el mismo ataque
    lejos_equipo = [alerta(1, dia=5, **host("WMS01")), alerta(2, dia=20, **host("WMS01"))]
    assert len(agrupar(lejos_equipo)) == 1  # el mismo equipo comprometido durante semanas sí


def test_el_mensaje_de_correo_une_el_aviso_y_el_clic():
    aviso = {**alerta(1, "UC-EML-001"), "evidence": {"message_id": "<m1@x>"}}
    clic = {**alerta(2, "UC-EML-003", hora=11), "evidence": {"message_id": "<m1@x>"}}
    assert len(agrupar([aviso, clic])) == 1


def test_el_filtro_de_relevantes_evita_que_el_ruido_una_grupos():
    puente = alerta(2, "UC-EML-001", **host("PC1"), **usuario("ana@tarvia.example"))
    otro_equipo = alerta(3, "UC-NET-002", **host("PC9"), **usuario("ana@tarvia.example"))
    real = alerta(1, "UC-EDR-001", **host("PC1"))
    todas = [real, puente, otro_equipo]
    assert len(agrupar(todas)[0]["alert_ids"]) == 3
    sin_ruido = agrupar(todas, es_relevante=lambda a: a["rule_id"] != "UC-EML-001")
    assert sin_ruido == []


def test_agrupar_no_modifica_las_alertas_originales():
    a = alerta(1, **host("PC1"))
    antes = repr(a)
    agrupar([a, alerta(2, **host("PC1"))])
    assert repr(a) == antes


# --- Un único ticket por grupo ---


def _resultado_de(alerta_, **opciones):
    ticket = resultado(alerta=alerta_, **opciones)
    return {"alert_id": alerta_["alert_id"], "ticket": ticket,
            "politica": {"severidad_final": ticket["severity"], "motivos_escalado": ticket["escalation"]["reason"].split("; ")}}


def test_consolidar_junta_las_alertas_en_un_ticket_valido_que_escala():
    a1 = {**alerta(1, "UC-EML-003", **host("PC1")), "severity": "medium", "mitre": {"technique_id": "T1566"}}
    a2 = {**alerta(2, "UC-EDR-001", hora=12, **host("PC1")), "mitre": {"technique_id": "T1204.002"}}
    resultados = {a["alert_id"]: _resultado_de(a, ejecucion_o_acceso_confirmado=a is a2) for a in (a1, a2)}
    grupo = agrupar([a1, a2])[0]
    t = consolidar_grupo(grupo, resultados)
    assert validar_ticket(t) == []
    assert t["alert_ids"] == grupo["alert_ids"] and t["ticket_id"] == "TKT-GRP-20261009-000001"
    assert t["severity"] == "critical" and t["decision"] == "escalar"
    assert t["escalation"]["escalate"] and "2 alertas relacionadas (2 reglas)" in t["escalation"]["reason"]
    assert {"T1566", "T1204.002"} <= set(t["mitre"])
    assert t["grupo"]["reglas"] == ["UC-EDR-001", "UC-EML-003"]
    assert EVIDENCIA["usuarios"] and t["executed_actions"] == []


def test_consolidar_ignora_alertas_sin_ticket_y_necesita_dos():
    a1, a2 = alerta(1, **host("PC1")), alerta(2, **host("PC1"))
    grupo = agrupar([a1, a2])[0]
    assert consolidar_grupo(grupo, {a1["alert_id"]: _resultado_de(a1), a2["alert_id"]: {"error": "x"}}) is None


def test_agrupar_resultados_solo_junta_lo_que_sigue_siendo_sospechoso():
    from src.agrupar import agrupar_resultados

    a1, a2, a3 = (alerta(n, regla, **host("PC1")) for n, regla in ((1, "UC-EML-003"), (2, "UC-EDR-001"), (3, "UC-NET-005")))
    resultados = {a["alert_id"]: _resultado_de(a) for a in (a1, a2, a3)}
    for a in (a1, a2):
        resultados[a["alert_id"]]["politica"]["veredicto"] = "true_positive"
    resultados[a3["alert_id"]]["politica"]["veredicto"] = "false_positive"
    grupos = agrupar_resultados(resultados, {a["alert_id"]: a for a in (a1, a2, a3)})
    assert len(grupos) == 1 and grupos[0]["alert_ids"] == [a1["alert_id"], a2["alert_id"]]
    assert grupos[0]["ticket"]["alert_ids"] == grupos[0]["alert_ids"] and grupos[0]["severidad"] == grupos[0]["ticket"]["severity"]


def test_las_acciones_repetidas_del_grupo_se_cuentan_una_vez():
    from src.agrupar import _acciones_unicas

    def accion(nombre, objetivo):
        return {"action": nombre, "target": objetivo}

    acciones = [
        accion("block_ioc", "IP 203.0.113.45 (AS64601)"),
        accion("block_ioc", "IP 203.0.113.45"),
        accion("block_ioc", "evil.example"),
        accion("revoke_sessions", "cuenta ana@tarvia.example"),
        accion("disable_user", "ana@tarvia.example"),  # otra acción sobre la misma cuenta: se conserva
        accion("revoke_sessions", "Sesión de ana@tarvia.example"),
    ]
    assert [(a["action"], a["target"]) for a in _acciones_unicas(acciones)] == [
        ("block_ioc", "IP 203.0.113.45 (AS64601)"), ("block_ioc", "evil.example"),
        ("revoke_sessions", "cuenta ana@tarvia.example"), ("disable_user", "ana@tarvia.example"),
    ]
