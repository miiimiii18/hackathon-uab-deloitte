"""Tests de src/soc_client.py. No necesitan la API: usan una función `obtener` falsa."""

import pytest

from src.soc_client import ErrorSOC, SocClient, coincide_exacto, ventana


class ApiFalsa:
    """Responde según un diccionario {ruta: (código, cuerpo)} y cuenta las llamadas."""

    def __init__(self, respuestas: dict):
        self.respuestas = respuestas
        self.llamadas: list[tuple[str, dict]] = []

    def __call__(self, ruta: str, params: dict):
        self.llamadas.append((ruta, params))
        return self.respuestas.get(ruta, (404, {"detail": "no existe"}))


def test_coincidencia_exacta_no_confunde_ips_ni_usuarios():
    assert coincide_exacto({"src_ip": "10.10.1.1"}, "10.10.1.1")
    assert not coincide_exacto({"src_ip": "10.10.1.185"}, "10.10.1.1")
    assert not coincide_exacto({"user": "carmen.serra2"}, "carmen.serra")
    assert coincide_exacto({"user": "TARVIA\\sergi.rubio"}, "sergi.rubio")
    assert coincide_exacto({"rcpt": ["sergi.rubio@tarvia.example"]}, "sergi.rubio")
    assert coincide_exacto({"detalle": {"anidado": "WS-BCN-1174"}}, "ws-bcn-1174")


def test_subdominios_solo_si_se_piden():
    evento = {"url": "https://www.wetransfer.com/upload"}
    assert not coincide_exacto(evento, "wetransfer.com")
    assert coincide_exacto(evento, "wetransfer.com", subdominios=True)
    assert not coincide_exacto({"q": "wetransfer.com.evil.example"}, "wetransfer.com", subdominios=True)


def test_ventana_de_24_horas_en_formato_de_los_logs():
    assert ventana("2026-10-05T07:56:30.000Z") == ("2026-10-04T07:56:30.000Z", "2026-10-06T07:56:30.000Z")


def test_404_es_desconocido_y_queda_en_la_traza():
    cliente = SocClient(obtener=ApiFalsa({}))
    assert cliente.activo("NO-EXISTE") is None
    assert cliente.traza[0]["desconocido"] is True
    assert cliente.traza[0]["resultados"] == 0


def test_la_cache_evita_repetir_consultas():
    api = ApiFalsa({"/users/ana@tarvia.example": (200, {"upn": "ana@tarvia.example"})})
    cliente = SocClient(obtener=api)
    cliente.usuario("ana@tarvia.example")
    cliente.usuario("ana@tarvia.example")
    assert len(api.llamadas) == 1
    assert [t["cache"] for t in cliente.traza] == [False, True]


def test_logs_filtra_por_coincidencia_exacta():
    items = [{"event_id": "PRX-1", "src_ip": "10.10.1.1"}, {"event_id": "PRX-2", "src_ip": "10.10.1.185"}]
    api = ApiFalsa({"/logs/proxy": (200, {"count": 2, "truncated": False, "items": items})})
    r = SocClient(obtener=api).logs("proxy", "10.10.1.1", "2026-10-04T00:00:00.000Z", "2026-10-06T00:00:00.000Z")
    assert [e["event_id"] for e in r["eventos"]] == ["PRX-1"]
    assert api.llamadas[0][1]["desde"] == "2026-10-04T00:00:00.000Z"


def test_evento_por_id_busca_en_su_fuente():
    items = [{"event_id": "EDR-0005329", "hostname": "WS-BCN-1174"}]
    api = ApiFalsa({"/logs/edr_events": (200, {"count": 1, "truncated": False, "items": items})})
    evento = SocClient(obtener=api).evento("EDR-0005329")
    assert evento == {"fuente": "edr_events", **items[0]}
    assert SocClient(obtener=api).evento("XYZ-1") is None


def test_error_del_servidor_da_error_claro():
    cliente = SocClient(obtener=ApiFalsa({"/alerts/ALR-1": (500, "fallo")}))
    with pytest.raises(ErrorSOC, match="500"):
        cliente.alerta("ALR-1")
