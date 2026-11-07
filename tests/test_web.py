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


def test_busca_en_el_dataset(cliente):
    assert [a["alert_id"] for a in cliente.get("/api/alertas", params={"q": "edr"}).json()] == ["ALR-2"]
    assert len(cliente.get("/api/alertas").json()) == 2
    assert cliente.get("/api/alertas/NO-EXISTE").status_code == 404


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


def test_una_alerta_pegada_sin_campos_se_rechaza_con_el_motivo(cliente):
    r = cliente.post("/api/triaje", json={"alertas": [{"alert_id": "X", "rule_id": "UC-1"}]})
    assert r.status_code == 422
    assert "severity" in r.json()["detail"] and "created_at" in r.json()["detail"] and "entities" in r.json()["detail"]


def test_una_alerta_pegada_completa_se_tria(cliente):
    alerta = {"alert_id": "NUEVA", "rule_id": "UC-1", "severity": "low", "created_at": "2026-11-08T09:00:00Z", "entities": {"hosts": [{"hostname": "H"}]}}
    evs = eventos(cliente.post("/api/triaje", json={"alertas": [alerta]}))
    assert next(e for e in evs if e["tipo"] == "resultado")["alert_id"] == "NUEVA"


def test_no_se_aceptan_rutas_a_ficheros(cliente):
    assert cliente.post("/api/triaje", json={"alertas": ["../../secreto.json"]}).status_code == 422


def test_modo_demo_reproduce_lo_guardado_sin_triar(cliente, monkeypatch):
    cliente.post("/api/triaje", json={"alertas": ["ALR-1"]})
    monkeypatch.setattr(api.time, "sleep", lambda s: None)
    monkeypatch.setattr(api, "triar", lambda *a, **k: pytest.fail("el modo demo no debe triar"))
    evs = eventos(cliente.post("/api/triaje", json={"alertas": ["ALR-1", "ALR-2"], "demo": True}))
    resumenes = {e["alert_id"]: e["resumen"] for e in evs if e["tipo"] == "resultado"}
    assert resumenes["ALR-1"]["decision"] == "escalar"
    assert "No hay resultado guardado" in resumenes["ALR-2"]["error"]


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
