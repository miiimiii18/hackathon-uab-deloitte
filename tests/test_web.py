"""Tests de la interfaz web (src/web/api.py). Sin red: el triaje, el LLM y la API del SOC son falsos."""

import json

import pytest
from fastapi.testclient import TestClient

from src.web import api

ALERTAS = [
    {"alert_id": "ALR-1", "rule_id": "UC-WEB-001", "rule_name": "Inyección web", "severity": "low",
     "source_product": "WAF", "created_at": "2026-10-08T10:43:12.000Z"},
    {"alert_id": "ALR-2", "rule_id": "UC-EDR-001", "rule_name": "Proceso hijo sospechoso", "severity": "high",
     "source_product": "EDR", "created_at": "2026-10-09T09:31:10.000Z"},
]


def _resultado(alerta):
    return {
        "alert_id": alerta["alert_id"],
        "traza": [],
        "evidencia": {},
        "llm": {"modelo": "ornith"},
        "politica": {"veredicto": "true_positive", "veredicto_llm": "true_positive", "severidad_final": "high", "decision": "escalar"},
        "ticket": {
            "ticket_id": "TKT-1", "title": "Ticket de prueba", "confidence": 0.9, "triage_seconds": 1,
            "recommended_actions": [
                {"action": "isolate_host", "target": "WS-1", "requires_approval": True, "permitida": True, "aprobador": "N2"},
                {"action": "close", "target": "ticket", "requires_approval": False, "permitida": True},
            ],
            "executed_actions": [],
        },
    }


@pytest.fixture
def cliente(tmp_path, monkeypatch):
    muestra = tmp_path / "muestra.jsonl"
    muestra.write_text("\n".join(json.dumps(a) for a in ALERTAS), encoding="utf-8")
    monkeypatch.setattr(api, "RUTA_ALERTAS", tmp_path / "no-existe.jsonl")
    monkeypatch.setattr(api, "RUTA_MUESTRA", muestra)
    monkeypatch.setattr(api, "CARPETAS_RESULTADOS", [tmp_path / "web", tmp_path / "demo"])
    monkeypatch.setattr(api, "_indice_cache", {})
    monkeypatch.setattr(api, "_completas_cache", {})
    monkeypatch.setattr(api, "_resultados", {})
    monkeypatch.setattr(api, "_disco_leido", False)

    def triar_falso(alerta, *, cliente=None, con_llm=True, enviar=None):
        enviar({})  # el servidor avisa de las etapas «ia» y «politica» al pasar por aquí
        return _resultado(alerta)

    monkeypatch.setattr(api, "triar", triar_falso)
    monkeypatch.setattr(api, "SocClient", lambda: object())
    monkeypatch.setattr(api, "cargar_alerta", lambda ref, cliente: next(a for a in ALERTAS if a["alert_id"] == ref))
    monkeypatch.setattr(api.llm, "llamar_api", lambda peticion: {})
    monkeypatch.setattr(api, "_modelos_disponibles", lambda: None)  # sin consultar al servidor del LLM
    return TestClient(api.app)


def eventos(respuesta):
    return [json.loads(b[6:]) for b in respuesta.text.split("\n\n") if b.startswith("data: ")]


def test_se_sirve_el_front_y_los_js_como_modulos(cliente):
    assert "TEMIPO" in cliente.get("/").text
    r = cliente.get("/js/main.js")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/javascript")
    assert r.headers["cache-control"] == "no-cache"  # tras actualizar el código no se mezclan JS viejos y CSS nuevo


def test_el_resumen_trae_las_razones_y_las_consultas():
    r = {
        "alert_id": "ALR-9",
        "traza": [{}, {}, {}],
        "evidencia": {"inteligencia": [{"estado": "malicious"}, {"estado": "unknown"}, {"estado": "clean"}]},
        "llm": {"analisis": {"evidence": [{"event_id": "EDR-1", "finding": "Ejecuta una DLL"}]}},
        "politica": {"veredicto": "needs_more_info", "veredicto_llm": "benign_true_positive",
                     "avisos": ["La autorización no encaja"], "severidad_regla": "low", "criticidad": "Crítica", "ajuste": -1},
        "ticket": {},
    }
    s = api.resumen_resultado(r)
    assert s["razon_ia"] == {"texto": "Ejecuta una DLL", "cita": "EDR-1"}
    assert s["razon_codigo"] == "La autorización no encaja"  # el código corrige a la IA: se dice por qué
    assert s["consultas"] == {"total": 3, "malicioso": 1, "desconocido": 1, "limpio": 1}
    assert (s["severidad_regla"], s["criticidad"], s["ajuste"]) == ("low", "Crítica", -1)
    r["politica"] |= {"veredicto": "benign_true_positive", "autorizacion": "CHG-1: pentest"}
    assert api.resumen_resultado(r)["razon_codigo"] == "Autorización verificada: CHG-1: pentest"


def test_busca_en_el_dataset(cliente):
    assert [a["alert_id"] for a in cliente.get("/api/alertas", params={"q": "edr"}).json()] == ["ALR-2"]
    assert len(cliente.get("/api/alertas").json()) == 2
    assert cliente.get("/api/alertas/NO-EXISTE").status_code == 404


def test_con_texto_busca_en_todo_el_dataset_y_sin_texto_lista_la_muestra(cliente, tmp_path, monkeypatch):
    fuera = {"alert_id": "ALR-3", "rule_id": "UC-OT-001", "rule_name": "Acceso a OT", "severity": "high",
             "source_product": "FW", "created_at": "2026-10-09T11:00:00.000Z"}
    completo = tmp_path / "alertas.jsonl"
    completo.write_text("\n".join(json.dumps(a) for a in [*ALERTAS, fuera]), encoding="utf-8")
    monkeypatch.setattr(api, "RUTA_ALERTAS", completo)
    monkeypatch.setattr(api, "_indice_cache", {})
    assert [a["alert_id"] for a in cliente.get("/api/alertas", params={"q": "ALR-3"}).json()] == ["ALR-3"]
    assert [a["alert_id"] for a in cliente.get("/api/alertas", params={"q": "uc-ot-001"}).json()] == ["ALR-3"]
    assert [a["alert_id"] for a in cliente.get("/api/alertas").json()] == ["ALR-1", "ALR-2"]


def test_el_triaje_envia_las_etapas_y_guarda_el_resultado(cliente, tmp_path):
    r = cliente.post("/api/triaje", json={"alertas": ["ALR-1", "ALR-2"], "paralelo": 2})
    evs = eventos(r)
    assert evs[0]["tipo"] == "inicio" and evs[-1]["tipo"] == "fin"
    etapas = [e["etapa"] for e in evs if e["tipo"] == "etapa" and e["alert_id"] == "ALR-1"]
    assert etapas == ["evidencia", "ia", "politica"]
    resumenes = {e["alert_id"]: e["resumen"] for e in evs if e["tipo"] == "resultado"}
    assert resumenes["ALR-2"]["decision"] == "escalar" and resumenes["ALR-2"]["severidad"] == "high"
    assert (tmp_path / "web" / "ALR-1.json").exists()
    assert cliente.get("/api/resultados/ALR-1").json()["ticket"]["ticket_id"] == "TKT-1"
    assert len(cliente.get("/api/resultados").json()) == 2


def test_solo_se_rechaza_una_alerta_pegada_sin_nada_que_investigar(cliente):
    r = cliente.post("/api/triaje", json={"alertas": [{"alert_id": "X", "severity": "high"}]})
    assert r.status_code == 422 and "nada que investigar" in r.json()["detail"]


def test_una_alerta_pegada_pobre_se_tria_y_sin_alert_id_recibe_uno_estable(cliente):
    pobre = {"rule_id": "UC-1", "entities": {"hosts": ["H"]}}
    evs = eventos(cliente.post("/api/triaje", json={"alertas": [pobre, {"alert_id": "SOLO-REGLA", "rule_id": "UC-2"}]}))
    ids = sorted(e["alert_id"] for e in evs if e["tipo"] == "resultado")
    assert ids[0].startswith("ALR-MANUAL-") and ids[1] == "SOLO-REGLA"
    otra_vez = eventos(cliente.post("/api/triaje", json={"alertas": [pobre]}))
    assert next(e for e in otra_vez if e["tipo"] == "resultado")["alert_id"] == ids[0]


def test_una_alerta_pegada_completa_se_tria(cliente):
    alerta = {"alert_id": "NUEVA", "rule_id": "UC-1", "severity": "low", "created_at": "2026-11-08T09:00:00Z", "entities": {"hosts": [{"hostname": "H"}]}}
    evs = eventos(cliente.post("/api/triaje", json={"alertas": [alerta]}))
    assert next(e for e in evs if e["tipo"] == "resultado")["alert_id"] == "NUEVA"


def _identicas():
    base = {"rule_id": "UC-1", "severity": "low", "created_at": "2026-11-08T09:00:00Z",
            "entities": {"hosts": [{"hostname": "H"}]}, "evidence": {"x": 1}}
    return [{**base, "alert_id": "ORIG"}, {**base, "alert_id": "COPIA", "created_at": "2026-11-08T10:00:00Z"}]


def test_las_alertas_identicas_se_trian_una_vez_y_la_copia_se_guarda(cliente, monkeypatch, tmp_path):
    triadas = []

    def triar_contando(alerta, **k):
        triadas.append(alerta["alert_id"])
        return _resultado(alerta)

    monkeypatch.setattr(api, "triar", triar_contando)
    evs = eventos(cliente.post("/api/triaje", json={"alertas": _identicas()}))
    assert triadas == ["ORIG"]
    assert evs[0]["duplicadas"] == 1
    resultados = {e["posicion"]: e for e in evs if e["tipo"] == "resultado"}
    assert resultados[1]["alert_id"] == "COPIA" and resultados[1]["resumen"]["duplicada_de"] == "ORIG"
    assert resultados[1]["resumen"]["decision"] == "escalar"
    guardada = cliente.get("/api/resultados/COPIA").json()
    assert guardada["duplicada_de"] == "ORIG" and guardada["alerta"]["created_at"] == "2026-11-08T10:00:00Z"
    assert (tmp_path / "web" / "COPIA.json").exists()
    assert "duplicada_de" not in cliente.get("/api/resultados/ORIG").json()


def test_las_distintas_no_se_marcan_como_duplicadas(cliente):
    evs = eventos(cliente.post("/api/triaje", json={"alertas": ["ALR-1", "ALR-2"]}))
    assert evs[0]["duplicadas"] == 0
    assert all(not e["resumen"].get("duplicada_de") for e in evs if e["tipo"] == "resultado")


def test_no_se_aceptan_rutas_a_ficheros(cliente):
    assert cliente.post("/api/triaje", json={"alertas": ["../../secreto.json"]}).status_code == 422


def test_un_fallo_en_una_alerta_no_para_el_lote(cliente, monkeypatch):
    def rota(alerta, **k):
        if alerta["alert_id"] == "ALR-1":
            raise ValueError("alerta mal formada")
        return _resultado(alerta)

    monkeypatch.setattr(api, "triar", rota)
    evs = eventos(cliente.post("/api/triaje", json={"alertas": ["ALR-1", "ALR-2"]}))
    resumenes = {e["alert_id"]: e["resumen"] for e in evs if e["tipo"] == "resultado"}
    assert "alerta mal formada" in resumenes["ALR-1"]["error"] and "error" not in resumenes["ALR-2"]


def test_el_resultado_lleva_la_hora_del_triaje(cliente):
    evs = eventos(cliente.post("/api/triaje", json={"alertas": ["ALR-1"]}))
    resumen = next(e for e in evs if e["tipo"] == "resultado")["resumen"]
    assert resumen["triado_en"].startswith("20")  # el navegador lo usa para recuperar resultados si se corta la conexión


def test_si_falla_el_resumen_la_fila_recibe_igualmente_su_resultado(cliente, monkeypatch):
    def rota(r):
        raise ValueError("resumen roto")

    monkeypatch.setattr(api, "resumen_resultado", rota)
    evs = eventos(cliente.post("/api/triaje", json={"alertas": ["ALR-1"]}))
    assert evs[-1]["tipo"] == "fin"  # el flujo no se queda colgado
    assert "resumen roto" in next(e for e in evs if e["tipo"] == "resultado")["resumen"]["error"]


def test_contencion_sin_aprobador_no_se_ejecuta(cliente):
    cliente.post("/api/triaje", json={"alertas": ["ALR-1"]})
    r = cliente.post("/api/resultados/ALR-1/acciones/0/ejecutar", json={})
    assert r.status_code == 400 and "necesita la aprobación de N2" in r.json()["detail"]
    assert cliente.get("/api/resultados/ALR-1").json()["ticket"]["executed_actions"] == []


def test_cerrar_o_revisar_no_son_contencion(cliente):
    cliente.post("/api/triaje", json={"alertas": ["ALR-1"]})
    r = cliente.post("/api/resultados/ALR-1/acciones/1/ejecutar", json={"aprobador": "N2 - Ana"})
    assert r.status_code == 400 and "no es una acción de contención" in r.json()["detail"]
    assert cliente.post("/api/resultados/ALR-1/acciones/9/ejecutar", json={}).status_code == 404


def test_contencion_aprobada_se_registra_y_no_se_repite(cliente, monkeypatch):
    cliente.post("/api/triaje", json={"alertas": ["ALR-1"]})
    registro = {"action": "isolate_host", "target": "WS-1", "approved_by": "N2 - Ana", "result": "ok (simulado)"}
    monkeypatch.setattr(api, "ejecutar_accion", lambda accion, **k: [registro])
    r = cliente.post("/api/resultados/ALR-1/acciones/0/ejecutar", json={"aprobador": "N2 - Ana"})
    assert r.status_code == 200 and r.json()["executed_actions"] == [registro]
    assert cliente.get("/api/resultados/ALR-1").json()["ticket"]["executed_actions"] == [registro]
    assert cliente.post("/api/resultados/ALR-1/acciones/0/ejecutar", json={"aprobador": "N2 - Ana"}).status_code == 409


def test_la_decision_humana_pide_nombre(cliente):
    cliente.post("/api/triaje", json={"alertas": ["ALR-1"]})
    assert cliente.post("/api/resultados/ALR-1/decisiones", json={"tipo": "cerrar"}).status_code == 400
    assert cliente.post("/api/resultados/ALR-1/decisiones", json={"tipo": "borrar_todo", "por": "x"}).status_code == 422
    r = cliente.post("/api/resultados/ALR-1/decisiones", json={"tipo": "cerrar", "por": "N1 - Pol"})
    assert r.json()["humano"][0]["por"] == "N1 - Pol"
    assert next(x for x in cliente.get("/api/resultados").json() if x["alert_id"] == "ALR-1")["resuelta"] is True


def test_si_el_modelo_de_env_no_existe_se_usa_el_de_la_organizacion(cliente, monkeypatch):
    monkeypatch.setattr(api.llm, "MODELO_POR_DEFECTO", "qwen3:8b")
    monkeypatch.setattr(api.llm, "API_KEY", "clave-de-prueba")
    monkeypatch.setattr(api, "_modelos_disponibles", lambda: ["ornith"])
    peticiones = []
    monkeypatch.setattr(api.llm, "llamar_api", lambda peticion: peticiones.append(peticion) or {})
    estado = cliente.get("/api/estado").json()
    assert estado["modelo"] == "ornith" and estado["llm"] is True
    assert "qwen3:8b" in estado["llm_aviso"] and "LLM_MODEL=ornith" in estado["llm_aviso"]
    evs = eventos(cliente.post("/api/triaje", json={"alertas": ["ALR-1"]}))
    assert any(e["tipo"] == "resultado" for e in evs)
    assert peticiones and peticiones[0]["model"] == "ornith"


def test_sin_clave_o_sin_modelo_el_estado_lo_dice(cliente, monkeypatch):
    monkeypatch.setattr(api.llm, "API_KEY", "")
    estado = cliente.get("/api/estado").json()
    assert estado["llm"] is False and "LLM_API_KEY" in estado["llm_aviso"]
    monkeypatch.setattr(api.llm, "API_KEY", "clave-de-prueba")
    monkeypatch.setattr(api.llm, "MODELO_POR_DEFECTO", "qwen3:8b")
    monkeypatch.setattr(api, "_modelos_disponibles", lambda: ["otro"])
    estado = cliente.get("/api/estado").json()
    assert estado["llm"] is False and "no existe" in estado["llm_aviso"]


def test_el_nombre_del_fichero_no_puede_salir_de_la_carpeta():
    nombre = api._nombre_seguro("../../etc/passwd")
    assert "/" not in nombre and "\\" not in nombre and not nombre.startswith(".")


def test_grupos_junta_en_un_ticket_las_alertas_triadas_del_mismo_ataque(cliente):
    from tests.test_agrupar import _resultado_de, alerta, host

    a1, a2 = alerta(1, "UC-EML-003", **host("PC1")), alerta(2, "UC-EDR-001", hora=12, **host("PC1"))
    for a in (a1, a2):
        r = {**_resultado_de(a), "alerta": a}
        r["politica"]["veredicto"] = "true_positive"
        api._guardar(r)
    grupos = cliente.get("/api/grupos").json()
    assert len(grupos) == 1
    assert grupos[0]["alert_ids"] == [a1["alert_id"], a2["alert_id"]]
    assert grupos[0]["ticket"]["escalation"]["escalate"] is True
    assert cliente.get("/api/resultados").status_code == 200


def test_grupos_vacio_si_no_hay_nada_triado(cliente):
    assert cliente.get("/api/grupos").json() == []


def test_la_persona_corrige_el_veredicto_y_queda_anotado_sin_tocar_la_politica(cliente):
    cliente.post("/api/triaje", json={"alertas": ["ALR-1"]})
    url = "/api/resultados/ALR-1/decisiones"
    base = {"tipo": "corregir", "por": "N2 - Ana", "motivo": "Es la newsletter de siempre", "veredicto": "false_positive", "severidad": "informational"}
    assert cliente.post(url, json={**base, "motivo": ""}).status_code == 400
    assert cliente.post(url, json={**base, "por": " "}).status_code == 400
    assert cliente.post(url, json={**base, "veredicto": "inventado"}).status_code == 422
    assert cliente.post(url, json={**base, "severidad": "gravisima"}).status_code == 422
    assert cliente.post(url, json=base).status_code == 200
    resultado = cliente.get("/api/resultados/ALR-1").json()
    assert resultado["politica"]["veredicto"] == "true_positive"  # lo que decidió el código no cambia
    assert resultado["humano"][0]["veredicto"] == "false_positive" and resultado["humano"][0]["por"] == "N2 - Ana"
    resumen = next(x for x in cliente.get("/api/resultados").json() if x["alert_id"] == "ALR-1")
    assert resumen["correccion"]["veredicto"] == "false_positive"


def test_la_alerta_original_sale_del_resultado_o_del_dataset(cliente):
    assert cliente.get("/api/alertas/ALR-404/original").status_code == 404
    guardada = {"alert_id": "ALR-9", "rule_id": "UC-X", "entities": {"hosts": []}}
    api._guardar({**_resultado(guardada), "alerta": guardada})
    assert cliente.get("/api/alertas/ALR-9/original").json() == guardada
    assert cliente.get("/api/alertas/ALR-1/original").json()["rule_id"] == "UC-WEB-001"  # está en el dataset


def test_el_informe_de_investigacion_solo_se_genera_para_lo_escalado(cliente, monkeypatch):
    from tests.test_agrupar import _resultado_de, alerta, host

    a1, a2 = alerta(1, "UC-EML-003", **host("PC1")), alerta(2, "UC-EDR-001", hora=12, **host("PC1"))
    for a in (a1, a2):
        r = {**_resultado_de(a), "alerta": a}
        r["politica"]["veredicto"] = "true_positive"
        api._guardar(r)
    llamadas = []

    def investigar_falso(ticket, resultados, alertas, **opciones):
        llamadas.append(ticket["ticket_id"])
        assert [i["incident_id"] for i in opciones["otros_incidentes"]] == ["INC-GRP-20261009-000001"]
        return {"informe": {"incident_id": "INC-1", "alert_ids": ticket["alert_ids"]}, "informe_errores": [], "llm": {}}

    monkeypatch.setattr(api, "investigar", investigar_falso)
    assert cliente.get(f"/api/resultados/{a1['alert_id']}/informe").status_code == 404
    r = cliente.post(f"/api/resultados/{a1['alert_id']}/investigar")
    assert r.status_code == 200 and llamadas == ["TKT-GRP-20261009-000001"]  # el informe es del grupo entero
    for a in (a1, a2):
        guardado = cliente.get(f"/api/resultados/{a['alert_id']}/informe").json()
        assert guardado["informe"]["alert_ids"] == [a1["alert_id"], a2["alert_id"]]
    assert cliente.post("/api/resultados/ALR-404/investigar").status_code == 404


def test_no_se_investiga_lo_que_no_esta_escalado(cliente, monkeypatch):
    cliente.post("/api/triaje", json={"alertas": ["ALR-1"]})
    api._resultados["ALR-1"]["ticket"]["escalation"] = {"escalate": False}
    monkeypatch.setattr(api, "investigar", lambda *a, **k: pytest.fail("no debería investigar"))
    assert cliente.post("/api/resultados/ALR-1/investigar").status_code == 409


def test_casos_sospechosos_cuenta_cada_grupo_una_vez_y_marca_lo_que_esta_en_revision():
    def res(ticket_id, escala, veredicto="true_positive", **extra):
        return {"ticket": {"ticket_id": ticket_id, "escalation": {"escalate": escala}},
                "politica": {"veredicto": veredicto}, **extra}

    grupos_ = [{"alert_ids": ["A", "B"], "ticket": {"ticket_id": "TKT-GRP-A", "escalation": {"escalate": True}}}]
    resultados = {"A": res("TKT-A", True), "B": res("TKT-B", True), "C": res("TKT-C", True),
                  "D": res("TKT-D", False, "needs_more_info"), "E": res("TKT-E", False, "false_positive"),
                  "F": res("TKT-C", True, duplicada_de="C")}
    assert api.casos_sospechosos(resultados, grupos_) == [
        {"incident_id": "INC-GRP-A", "alert_ids": ["A", "B"]}, {"incident_id": "INC-C", "alert_ids": ["C"]},
        {"incident_id": "D (en revisión, sin escalar)", "alert_ids": ["D"]}]
