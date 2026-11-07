"""Triaje de una alerta de punta a punta: alerta → evidencia → análisis del LLM.

Uso (con la API del SOC arrancada y, para el análisis, LLM_API_KEY en .env):
    python -m src.triaje ALR-20261005-000301                  # alerta del dataset
    python -m src.triaje mi_alerta.json                       # alerta nueva en un fichero
    python -m src.triaje ALR-20261005-000301 --solo-evidencia # sin LLM: ver qué se consulta

Después del LLM, src/policy.py aplica la política del SOC en código: verifica el
veredicto, calcula la severidad final y decide escalado y permisos de contención.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from src.evidencia import reunir_evidencia
from src.llm import ErrorLLM, analizar_alerta
from src.policy import aplicar_politica
from src.soc_client import ErrorSOC, SocClient


def cargar_alerta(referencia: str, cliente: SocClient) -> dict[str, Any]:
    """Acepta un ID de alerta del dataset o la ruta a un fichero .json con la alerta."""
    if referencia.lower().endswith(".json"):
        return json.loads(Path(referencia).read_text(encoding="utf-8"))
    alerta = cliente.alerta(referencia)
    if alerta is None:
        raise ErrorSOC(f"La alerta {referencia} no existe en la API del SOC")
    return alerta


def triar(
    alerta: dict[str, Any],
    *,
    cliente: SocClient | None = None,
    con_llm: bool = True,
    enviar=None,
) -> dict[str, Any]:
    """Reúne la evidencia y, si con_llm, pide el análisis al modelo y aplica la política."""
    cliente = cliente or SocClient()
    inicio = time.perf_counter()
    evidencia = reunir_evidencia(alerta, cliente)
    resultado: dict[str, Any] = {
        "alert_id": alerta.get("alert_id"),
        "evidencia": evidencia,
        "traza": cliente.traza,
        "segundos_evidencia": round(time.perf_counter() - inicio, 1),
    }
    if con_llm:
        llm = analizar_alerta(alerta, evidencia, enviar=enviar)
        resultado["llm"] = llm.model_dump()
        # La IA propone; la política (código) decide severidad, escalado y permisos.
        resultado["politica"] = aplicar_politica(alerta, evidencia, llm.analisis).model_dump()
    return resultado


def _resumen_traza(traza: list[dict[str, Any]]) -> str:
    consultas = [t for t in traza if not t["cache"]]
    lentas = sorted(consultas, key=lambda t: t["ms"], reverse=True)[:3]
    detalle = ", ".join(f"{t['consulta']} {t['ms']} ms" for t in lentas)
    return f"{len(consultas)} consultas a la API ({len(traza) - len(consultas)} desde caché). Más lentas: {detalle}"


if __name__ == "__main__":
    argumentos = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(argumentos) != 1:
        raise SystemExit("Uso: python -m src.triaje <alert_id | fichero.json> [--solo-evidencia]")
    try:
        cliente = SocClient()
        alerta = cargar_alerta(argumentos[0], cliente)
        resultado = triar(alerta, cliente=cliente, con_llm="--solo-evidencia" not in sys.argv)
    except (ErrorSOC, ErrorLLM) as e:
        raise SystemExit(f"Error: {e}") from e
    print(json.dumps(resultado, ensure_ascii=False, indent=2))
    print(_resumen_traza(resultado["traza"]), f"| evidencia en {resultado['segundos_evidencia']} s", file=sys.stderr)
