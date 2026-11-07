"""Tests del triaje en lote (src/triaje.py). Se sustituye `triar` por uno falso: sin red."""

import threading
import time

import pytest

from src import triaje
from src.triaje import triar_en_paralelo, triar_lote


@pytest.fixture
def triar_falso(monkeypatch):
    """Cada «triaje» tarda 0,2 s y registra cuántos se ejecutan a la vez."""
    estado = {"activos": 0, "maximo": 0, "clientes": []}
    cerrojo = threading.Lock()

    def falso(alerta, *, cliente=None, con_llm=True, enviar=None):
        with cerrojo:
            estado["activos"] += 1
            estado["maximo"] = max(estado["maximo"], estado["activos"])
            estado["clientes"].append(cliente)
        time.sleep(0.2)
        with cerrojo:
            estado["activos"] -= 1
        if alerta["alert_id"] == "ROTA":
            raise ValueError("alerta mal formada")
        return {"alert_id": alerta["alert_id"], "con_llm": con_llm}

    monkeypatch.setattr(triaje, "triar", falso)
    return estado


ALERTAS = [{"alert_id": f"ALR-{i}"} for i in range(6)]


def test_el_lote_mantiene_el_orden(triar_falso):
    resultados = triar_lote(ALERTAS, en_paralelo=3, crear_cliente=object)
    assert [r["alert_id"] for r in resultados] == [a["alert_id"] for a in ALERTAS]


def test_en_paralelo_es_mas_rapido_y_respeta_el_limite(triar_falso):
    inicio = time.perf_counter()
    triar_lote(ALERTAS, en_paralelo=3, crear_cliente=object)
    duracion = time.perf_counter() - inicio
    assert triar_falso["maximo"] == 3  # nunca más de 3 a la vez
    assert duracion < 0.2 * len(ALERTAS) * 0.75  # en serie serían 1,2 s


def test_nunca_pasa_del_maximo_permitido(triar_falso):
    triar_lote([{"alert_id": f"A{i}"} for i in range(12)], en_paralelo=50, crear_cliente=object)
    assert triar_falso["maximo"] <= triaje.MAX_PARALELO


def test_cada_alerta_tiene_su_propio_cliente(triar_falso):
    triar_lote(ALERTAS, en_paralelo=3, crear_cliente=object)
    assert len({id(c) for c in triar_falso["clientes"]}) == len(ALERTAS)


def test_una_alerta_rota_no_para_el_lote(triar_falso):
    resultados = triar_lote([{"alert_id": "ALR-1"}, {"alert_id": "ROTA"}, {"alert_id": "ALR-2"}], crear_cliente=object)
    assert "error" in resultados[1] and "mal formada" in resultados[1]["error"]
    assert resultados[0]["alert_id"] == "ALR-1" and "error" not in resultados[2]
    assert all("segundos_total" in r for r in resultados)


def test_el_generador_devuelve_cada_alerta_al_terminar(triar_falso):
    vistas = sorted(i for i, _ in triar_en_paralelo(ALERTAS, en_paralelo=2, crear_cliente=object))
    assert vistas == list(range(len(ALERTAS)))


def test_solo_evidencia_se_propaga(triar_falso):
    r = triar_lote([{"alert_id": "ALR-1"}], con_llm=False, crear_cliente=object)
    assert r[0]["con_llm"] is False


def test_preparar_lote_marca_las_identicas_y_deja_las_que_no_cargan():
    base = {"rule_id": "UC-1", "entities": {"hosts": ["H"]}, "evidence": {"x": 1}}
    dataset = {"A": {**base, "alert_id": "A"}, "B": {**base, "alert_id": "B"}, "C": {**base, "rule_id": "UC-2", "alert_id": "C"}}

    class ClienteFalso:
        def alerta(self, ref):
            return dataset.get(ref)

    lote, duplicadas = triaje.preparar_lote(["A", "NO-EXISTE", "B", "C"], crear_cliente=ClienteFalso)
    assert duplicadas == {2: 0}
    assert lote[1] == "NO-EXISTE" and lote[0]["alert_id"] == "A"
    assert triaje.preparar_lote(["A", "B"], deduplicar=False, crear_cliente=ClienteFalso) == (["A", "B"], {})


def test_la_copia_de_una_duplicada_lleva_su_id_y_de_quien_es():
    original = {"alert_id": "A", "alerta": {"alert_id": "A"}, "ticket": {"ticket_id": "TKT-A"}}
    copia = triaje.copia_de_duplicada(original, {"alert_id": "B", "rule_id": "UC-1"})
    assert copia["alert_id"] == "B" and copia["duplicada_de"] == "A"
    assert copia["alerta"]["alert_id"] == "B" and copia["ticket"]["ticket_id"] == "TKT-A"
    assert original["alert_id"] == "A"  # la original no se toca
