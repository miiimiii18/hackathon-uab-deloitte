"""Tests de src/contencion.py con una API del SOC falsa (sin red)."""

import pytest

from src.contencion import (
    ErrorContencion,
    ejecutar_accion,
    objetivos,
    registrar_en_ticket,
)
from src.soc_client import SocClient


class ApiContencionFalsa:
    """Imita /approvals y /containment de la API simulada, con sus mismas reglas."""

    def __init__(self):
        self.aprobaciones: dict[str, dict] = {}
        self.ejecutadas: list[dict] = []

    def __call__(self, ruta: str, cuerpo: dict):
        if ruta == "/approvals":
            token = f"APR-{len(self.aprobaciones)}"
            self.aprobaciones[token] = cuerpo
            return 200, {"approval_token": token, **cuerpo}
        accion = ruta.rsplit("/", 1)[-1]
        if accion not in ("block_ioc", "purge_email"):
            ap = self.aprobaciones.get(cuerpo["approval_token"])
            if not ap or ap["action"] != accion or ap["target"] != cuerpo["target"]:
                return 403, {"detail": "falta aprobación humana válida para esta acción y objetivo"}
        self.ejecutadas.append({"action": accion, **cuerpo})
        return 200, {"timestamp": "2026-11-07T18:00:00Z", "action": accion, **cuerpo, "result": "ok (simulado)"}


@pytest.fixture
def api():
    return ApiContencionFalsa()


@pytest.fixture
def cliente(api):
    return SocClient(obtener=lambda r, p: (404, None), publicar=api)


def accion(nombre, target, requiere=True, aprobador="N2", permitida=True, nota=""):
    return {"action": nombre, "target": target, "justification": "contener", "requires_approval": requiere,
            "aprobador": aprobador, "permitida": permitida, "nota": nota}


def test_limpieza_de_objetivos():
    assert objetivos("isolate_host", "WS-BCN-1770 (10.10.3.95)") == ["WS-BCN-1770"]
    assert objetivos("block_ioc", "IP 203.0.113.88, dominio evil.example y hash abc123") == [
        "203.0.113.88", "evil.example", "abc123"]
    assert objetivos("revoke_sessions", "usuario ana@tarvia.example") == ["ana@tarvia.example"]
    assert objetivos("purge_email", "  ") == []


def test_accion_sin_aprobacion_la_ejecuta_el_n1(api, cliente):
    registros = ejecutar_accion(accion("block_ioc", "evil.example", requiere=False, aprobador="—"), cliente=cliente)
    assert registros[0]["approved_by"].startswith("N1") and registros[0]["approval_token"] == ""
    assert api.aprobaciones == {} and len(api.ejecutadas) == 1


def test_accion_con_aprobacion_pide_token_y_lo_usa(api, cliente):
    registros = ejecutar_accion(accion("isolate_host", "WS-BCN-1770 (10.10.3.95)"), aprobador="N2 - Ana",
                                ticket_id="TKT-1", cliente=cliente)
    assert registros[0]["target"] == "WS-BCN-1770"
    assert registros[0]["approved_by"] == "N2 - Ana" and registros[0]["approval_token"] == "APR-0"
    assert api.aprobaciones["APR-0"]["approver"] == "N2 - Ana"
    assert api.ejecutadas[0]["ticket_id"] == "TKT-1"
    # La traza registra las dos llamadas para enseñarlas en la UI.
    assert [t["consulta"] for t in cliente.traza] == ["POST /approvals", "POST /containment/isolate_host"]


def test_sin_aprobador_no_se_ejecuta_nada(api, cliente):
    with pytest.raises(ErrorContencion, match="necesita la aprobación de N2"):
        ejecutar_accion(accion("disable_user", "ana"), aprobador="  ", cliente=cliente)
    assert api.aprobaciones == {} and api.ejecutadas == []


def test_accion_prohibida_por_la_politica(api, cliente):
    ot = accion("isolate_host", "PLC-01", permitida=False, nota="Red OT: solo escalar a Operaciones.")
    with pytest.raises(ErrorContencion, match="Red OT"):
        ejecutar_accion(ot, aprobador="N2 - Ana", cliente=cliente)
    assert api.ejecutadas == []


def test_cerrar_o_revisar_no_son_contencion(cliente):
    with pytest.raises(ErrorContencion, match="no es una acción de contención"):
        ejecutar_accion(accion("close", "ticket", requiere=False), cliente=cliente)


def test_varios_ioc_se_bloquean_uno_a_uno(api, cliente):
    registros = ejecutar_accion(accion("block_ioc", "1.2.3.4, evil.example", requiere=False), cliente=cliente)
    assert [r["target"] for r in registros] == ["1.2.3.4", "evil.example"]
    assert len(api.ejecutadas) == 2


def test_un_rechazo_de_la_api_da_error_claro(cliente):
    def api_que_rechaza(ruta, cuerpo):
        return 403, {"detail": "política: el SOC no actúa sobre OT; escalar a Operaciones"}

    c = SocClient(obtener=lambda r, p: (404, None), publicar=api_que_rechaza)
    with pytest.raises(ErrorContencion, match="no actúa sobre OT"):
        ejecutar_accion(accion("block_ioc", "x.example", requiere=False), cliente=c)


def test_registrar_en_ticket():
    ticket = {"ticket_id": "TKT-1", "executed_actions": []}
    registrar_en_ticket(ticket, [{"action": "block_ioc", "target": "x"}])
    assert ticket["executed_actions"] == [{"action": "block_ioc", "target": "x"}]
