"""Triaje de una alerta de punta a punta: alerta → evidencia → análisis del LLM.

Uso (con la API del SOC arrancada y, para el análisis, LLM_API_KEY en .env):
    python -m src.triaje ALR-20261005-000301                  # alerta del dataset
    python -m src.triaje mi_alerta.json                       # alerta nueva en un fichero
    python -m src.triaje ALR-20261005-000301 --solo-evidencia # sin LLM: ver qué se consulta
    python -m src.triaje ALR-1 ALR-2 ALR-3 --salida data/out/lote   # varias, en paralelo

Después del LLM, src/policy.py aplica la política del SOC en código: verifica el
veredicto, calcula la severidad final y decide escalado y permisos de contención.

Varias alertas se trían EN PARALELO (hilos): casi todo el tiempo es esperar la
respuesta del servidor del DCC, que atiende varias peticiones a la vez.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from src.evidencia import normalizar_alerta, reunir_evidencia
from src.llm import ErrorLLM, analizar_alerta
from src.policy import aplicar_politica
from src.soc_client import ErrorSOC, SocClient
from src.ticket import construir_ticket, validar_ticket

# Alertas a la vez. El servidor del DCC lo comparten todos los equipos: con 4–6 se
# gana casi todo sin saturarlo. Se puede cambiar con TRIAJE_PARALELO en .env.
PARALELO = int(os.getenv("TRIAJE_PARALELO", "4"))
MAX_PARALELO = 8


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
    # Alertas de fuera del dataset pueden traer campos raros: se normalizan al entrar.
    alerta = normalizar_alerta(alerta)
    evidencia = reunir_evidencia(alerta, cliente)
    resultado: dict[str, Any] = {
        "alert_id": alerta.get("alert_id"),
        "alerta": alerta,  # la alerta ya normalizada: la UI la enseña y la agrupación la necesita
        "evidencia": evidencia,
        "traza": cliente.traza,
        "segundos_evidencia": round(time.perf_counter() - inicio, 1),
    }
    if con_llm:
        llm = analizar_alerta(alerta, evidencia, enviar=enviar)
        resultado["llm"] = llm.model_dump()
        # La IA propone; la política (código) decide severidad, escalado y permisos.
        resultado["politica"] = aplicar_politica(alerta, evidencia, llm.analisis).model_dump()
        # Ticket en el formato de Deloitte, validado contra su esquema.
        ticket = construir_ticket(alerta, evidencia, resultado["llm"], resultado["politica"],
                                  segundos=time.perf_counter() - inicio)
        resultado["ticket"] = ticket
        resultado["ticket_errores"] = validar_ticket(ticket)  # vacío = cumple el esquema
    return resultado


# --- Varias alertas en paralelo ----------------------------------------------------------

Referencia = str | dict[str, Any]  # ID del dataset, ruta a un .json o la alerta ya cargada


def _triar_una(referencia: Referencia, con_llm: bool, enviar, crear_cliente: Callable[[], SocClient]) -> dict[str, Any]:
    """Tría una alerta con su PROPIO cliente (la caché y la traza no se comparten entre hilos).

    Un fallo en una alerta no para el lote: se devuelve {"error": ...} para esa alerta.
    """
    inicio = time.perf_counter()
    nombre = referencia.get("alert_id", "?") if isinstance(referencia, dict) else referencia
    try:
        cliente = crear_cliente()
        alerta = referencia if isinstance(referencia, dict) else cargar_alerta(referencia, cliente)
        resultado = triar(alerta, cliente=cliente, con_llm=con_llm, enviar=enviar)
    except Exception as e:  # noqa: BLE001 — en un lote, cualquier fallo se informa y se sigue
        resultado = {"alert_id": nombre, "error": f"{type(e).__name__}: {e}"}
    resultado["segundos_total"] = round(time.perf_counter() - inicio, 1)
    return resultado


def triar_en_paralelo(
    referencias: list[Referencia],
    *,
    en_paralelo: int = PARALELO,
    con_llm: bool = True,
    enviar=None,
    crear_cliente: Callable[[], SocClient] = SocClient,
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Tría varias alertas a la vez y devuelve (posición, resultado) según van terminando.

    Pensado para la UI: cada alerta se puede mostrar en cuanto está lista, sin esperar
    a las demás. La posición indica a qué alerta de `referencias` corresponde.
    """
    hilos = max(1, min(en_paralelo, MAX_PARALELO, len(referencias) or 1))
    with ThreadPoolExecutor(max_workers=hilos) as ejecutor:
        futuros = {
            ejecutor.submit(_triar_una, ref, con_llm, enviar, crear_cliente): i
            for i, ref in enumerate(referencias)
        }
        for futuro in as_completed(futuros):
            yield futuros[futuro], futuro.result()


def triar_lote(referencias: list[Referencia], **opciones) -> list[dict[str, Any]]:
    """Como triar_en_paralelo, pero espera a todas y las devuelve en el orden original."""
    resultados: list[dict[str, Any]] = [{} for _ in referencias]
    for i, resultado in triar_en_paralelo(referencias, **opciones):
        resultados[i] = resultado
    return resultados


# --- Línea de comandos --------------------------------------------------------------------


def _resumen_traza(traza: list[dict[str, Any]]) -> str:
    consultas = [t for t in traza if not t["cache"]]
    lentas = sorted(consultas, key=lambda t: t["ms"], reverse=True)[:3]
    detalle = ", ".join(f"{t['consulta']} {t['ms']} ms" for t in lentas)
    return f"{len(consultas)} consultas a la API ({len(traza) - len(consultas)} desde caché). Más lentas: {detalle}"


def _linea(resultado: dict[str, Any]) -> str:
    if "error" in resultado:
        return f"ERROR: {resultado['error']}"
    p = resultado.get("politica")
    if not p:
        return f"evidencia en {resultado['segundos_evidencia']} s"
    return f"{p['veredicto']} → {p['severidad_final']}, {p['decision']}"


def _principal() -> None:
    parser = argparse.ArgumentParser(prog="python -m src.triaje", description="Triaje N1 de alertas del SOC de Tarvia")
    parser.add_argument("alertas", nargs="+", help="IDs de alerta del dataset o ficheros .json")
    parser.add_argument("--solo-evidencia", action="store_true", help="no llamar al LLM")
    parser.add_argument("--paralelo", type=int, default=PARALELO, help=f"alertas a la vez (máx. {MAX_PARALELO})")
    parser.add_argument("--salida", type=Path, help="carpeta donde guardar un .json por alerta")
    args = parser.parse_args()
    con_llm = not args.solo_evidencia

    # Una sola alerta y sin carpeta de salida: se imprime el resultado completo.
    if len(args.alertas) == 1 and args.salida is None:
        try:
            cliente = SocClient()
            resultado = triar(cargar_alerta(args.alertas[0], cliente), cliente=cliente, con_llm=con_llm)
        except (ErrorSOC, ErrorLLM) as e:
            raise SystemExit(f"Error: {e}") from e
        print(json.dumps(resultado, ensure_ascii=False, indent=2))
        print(_resumen_traza(resultado["traza"]), f"| evidencia en {resultado['segundos_evidencia']} s", file=sys.stderr)
        return

    if args.salida:
        args.salida.mkdir(parents=True, exist_ok=True)
    n = len(args.alertas)
    inicio = time.perf_counter()
    resultados: list[dict[str, Any]] = [{} for _ in args.alertas]
    for hechas, (i, r) in enumerate(triar_en_paralelo(args.alertas, en_paralelo=args.paralelo, con_llm=con_llm), 1):
        resultados[i] = r
        print(f"[{hechas}/{n}] {r.get('alert_id')}: {_linea(r)} ({r['segundos_total']} s)", file=sys.stderr)
        if args.salida:
            nombre = Path(str(r.get("alert_id") or f"alerta-{i}")).stem
            (args.salida / f"{nombre}.json").write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
    total = time.perf_counter() - inicio
    errores = sum(1 for r in resultados if "error" in r)
    print(
        f"{n} alertas en {total:.1f} s ({total / n:.1f} s por alerta de media) con "
        f"{min(args.paralelo, MAX_PARALELO)} en paralelo" + (f" | {errores} con error" if errores else ""),
        file=sys.stderr,
    )
    if args.salida is None:
        print(json.dumps(resultados, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _principal()
