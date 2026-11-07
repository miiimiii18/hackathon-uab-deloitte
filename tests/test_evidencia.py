"""Tests de src/evidencia.py con un cliente del SOC falso (sin API)."""

import json

from src import evidencia
from src.evidencia import (
    entidades,
    es_ip_interna,
    estado_intel,
    reunir_evidencia,
    terminos_de_busqueda,
)

ALERTA = {
    "alert_id": "ALR-1",
    "created_at": "2026-10-05T08:00:00.000Z",
    "runbook": "RB-04",
    "entities": {
        "users": [{"upn": "carmen.serra@tarvia.example"}, {"upn": "(12 cuentas)"}],
        "hosts": [{"hostname": "WS-BCN-1375", "ip": "10.10.2.136"}],
        "domains": ["wetransfer.com"],
    },
    "related_events": ["DLP-0000115"],
}


class ClienteFalso:
    """Imita SocClient con datos fijos."""

    def __init__(self, n_eventos: int = 3):
        self.n = n_eventos
        self.busquedas: list[tuple[str, str]] = []

    def activo(self, h):
        return None  # equipo no gestionado

    def usuario(self, upn):
        return {"upn": upn, "department": "E-commerce", "notes": ""}

    def intel(self, ind):
        return {"tip": {"reputation": "benign"}, "geo": None}

    def sandbox(self, sha):
        return None

    def cambios(self, texto):
        return [{"id": "CHG-1", "titulo": "cambio"}] if texto == "carmen.serra" else []

    def evento(self, event_id, desde=None, hasta=None):
        return {"fuente": "dlp", "event_id": event_id, "timestamp": "2026-10-05T07:59:00.000Z"}

    def logs(self, fuente, termino, desde=None, hasta=None, *, limite=200, subdominios=False):
        self.busquedas.append((fuente, termino))
        eventos = [
            {"event_id": f"{fuente}-{i}", "timestamp": f"2026-10-05T{i:02d}:00:00.000Z", "texto": "x" * 50}
            for i in range(self.n)
        ]
        return {"total": len(eventos), "truncado": False, "eventos": eventos}


def test_entidades_ignora_marcadores_y_separa_tipos():
    e = entidades(ALERTA)
    assert e["usuarios"] == ["carmen.serra@tarvia.example"]
    assert e["hosts"] == ["WS-BCN-1375"]
    assert e["ips"] == ["10.10.2.136"]
    assert e["dominios"] == ["wetransfer.com"]


def test_ips_internas_y_las_de_internet_del_dataset():
    assert es_ip_interna("10.10.2.136")
    # 198.18.x.x y 203.0.113.x hacen de IPs de internet en el dataset
    assert not es_ip_interna("198.18.58.60")
    assert not es_ip_interna("203.0.113.88")


def test_la_ip_interna_no_se_busca_si_ya_hay_hostname():
    terminos = terminos_de_busqueda(entidades(ALERTA))
    assert ("usuario", "carmen.serra") in terminos
    assert ("host", "WS-BCN-1375") in terminos
    assert all(t != ("ip", "10.10.2.136") for t in terminos)


def test_estado_intel_desconocido_nunca_es_limpio():
    assert estado_intel(None) == "unknown"
    assert estado_intel({"reputation": "benign"}) == "clean"
    assert estado_intel({"reputation": "suspicious"}) == "suspicious"


def test_reunir_evidencia_completa():
    cliente = ClienteFalso()
    ev = reunir_evidencia(ALERTA, cliente)

    assert ev["activos"]["WS-BCN-1375"].startswith("DESCONOCIDO")
    assert ev["usuarios"]["carmen.serra@tarvia.example"]["department"] == "E-commerce"
    assert "notes" not in ev["usuarios"]["carmen.serra@tarvia.example"]  # campos vacíos fuera
    assert ev["inteligencia"][0]["estado"] == "clean"
    assert [c["id"] for c in ev["cambios_aprobados"]] == ["CHG-1"]
    assert ev["eventos_citados_en_la_alerta"][0]["event_id"] == "DLP-0000115"
    # RB-04 → fuentes de fuga de datos
    assert {f for f, _ in cliente.busquedas} == {"dlp", "proxy", "edr_events", "email"}
    assert all(len(g["muestra"]) == 3 for g in ev["contexto_logs"])


def test_la_evidencia_se_recorta_si_no_cabe(monkeypatch):
    monkeypatch.setattr(evidencia, "MAX_CARACTERES", 6000)
    ev = reunir_evidencia(ALERTA, ClienteFalso(n_eventos=20))
    assert len(json.dumps(ev, ensure_ascii=False)) <= 6000
    # Se mantiene el recuento total aunque se muestren menos ejemplos
    assert all(g["total"] == 20 for g in ev["contexto_logs"])
