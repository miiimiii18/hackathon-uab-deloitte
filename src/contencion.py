"""Ejecución de la contención con aprobación humana (nivel 4, contra la API simulada).

Reparto de papeles (criterio de Deloitte: «qué decide la IA y qué decide la persona»):
- El LLM SUGIERE acciones; nunca las ejecuta.
- La política (src/policy.py) decide si una acción está permitida y quién la aprueba.
- Una PERSONA pulsa «ejecutar» en la UI. Si la acción necesita aprobación, la persona
  dice quién la aprueba; el código nunca se aprueba a sí mismo.
- Este módulo hace las llamadas: POST /approvals (si hace falta) y POST /containment.

Nada sale del portátil: la API simulada solo escribe en containment_log.jsonl.

Uso sin interfaz (para probar o para la demo):
    python -m src.contencion data/out/lote/ALR-....json 0 --aprobador "N2 - Ana" --motivo "malware confirmado"
    python -m src.contencion --registro
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from src.soc_client import ErrorSOC, SocClient

# Acciones que existen en la API simulada.
ACCIONES_API = {
    "isolate_host",
    "disable_user",
    "revoke_sessions",
    "reset_password",
    "block_ioc",
    "purge_email",
    "disable_access_key",
}

# Palabras que el LLM a veces pone delante del objetivo («IP 1.2.3.4», «dominio x.com»...).
PREFIJOS = re.compile(r"^(ip|dominio|domain|hash|sha256|host|equipo|usuario|user|cuenta|sesi[oó]n|correo|url)\s+", re.IGNORECASE)


class ErrorContencion(Exception):
    """La acción no se puede ejecutar (prohibida, sin aprobación, sin objetivo...)."""


def objetivos(accion: str, objetivo: str) -> list[str]:
    """Limpia el objetivo que sugiere el LLM y lo separa si hay varios IOC.

    «WS-BCN-1770 (10.10.3.95)» → ["WS-BCN-1770"]
    «IP 203.0.113.88, dominio evil.example y hash abc...» → ["203.0.113.88", "evil.example", "abc..."]
    """
    texto = re.sub(r"\s*\([^)]*\)", "", objetivo or "").strip()  # quita lo que va entre paréntesis
    trozos = re.split(r"\s*[,;]\s*|\s+y\s+", texto) if accion == "block_ioc" else [texto]
    limpios = [PREFIJOS.sub("", t.strip()).strip() for t in trozos]
    return [t for t in limpios if t]


def ejecutar_accion(
    accion: dict[str, Any],
    *,
    aprobador: str = "",
    motivo: str = "",
    ticket_id: str = "",
    cliente: SocClient | None = None,
) -> list[dict[str, Any]]:
    """Ejecuta una acción recomendada (de `politica["acciones"]` o del ticket).

    `aprobador`: nombre y rol de la PERSONA que aprueba (p. ej., «N2 - Ana López»).
    Obligatorio si la acción requiere aprobación. Devuelve un registro por objetivo,
    listo para añadir a `executed_actions` del ticket.
    """
    nombre = accion.get("action", "")
    if nombre not in ACCIONES_API:
        raise ErrorContencion(f"«{nombre}» no es una acción de contención de la API (cerrar o revisar no se ejecutan)")
    if not accion.get("permitida", True):
        raise ErrorContencion(f"Prohibida por la política: {accion.get('nota') or 'no se permite esta acción'}")
    requiere = bool(accion.get("requires_approval", True))
    if requiere and not aprobador.strip():
        raise ErrorContencion(
            f"Esta acción necesita la aprobación de {accion.get('aprobador') or 'N2'}: "
            "indica el nombre de la persona que la aprueba"
        )
    lista = objetivos(nombre, accion.get("target", ""))
    if not lista:
        raise ErrorContencion("La acción no tiene un objetivo concreto: revísala antes de ejecutarla")

    cliente = cliente or SocClient()
    justificacion = accion.get("justification", "") or motivo
    registros: list[dict[str, Any]] = []
    try:
        for objetivo in lista:
            # La API exige que el token sea para ESTA acción y ESTE objetivo.
            token = cliente.aprobar(nombre, objetivo, aprobador.strip(), motivo or justificacion) if requiere else ""
            r = cliente.contener(nombre, objetivo, justificacion, token, ticket_id)
            registros.append({
                "action": nombre,
                "target": objetivo,
                "approved_by": aprobador.strip() if requiere else "N1 (no requiere aprobación)",
                "approval_token": token,
                "result": r.get("result", ""),
                "timestamp": r.get("timestamp", ""),
                "ticket_id": ticket_id,
            })
    except ErrorSOC as e:
        raise ErrorContencion(str(e)) from e
    return registros


def registrar_en_ticket(ticket: dict[str, Any], registros: list[dict[str, Any]]) -> dict[str, Any]:
    """Añade las acciones ejecutadas al ticket (campo oficial `executed_actions`)."""
    ticket.setdefault("executed_actions", []).extend(registros)
    return ticket


# --- Línea de comandos --------------------------------------------------------------------


def _principal() -> None:
    parser = argparse.ArgumentParser(prog="python -m src.contencion", description="Ejecuta una acción de contención aprobada")
    parser.add_argument("resultado", nargs="?", type=Path, help="fichero .json de un triaje (python -m src.triaje ... --salida)")
    parser.add_argument("indice", nargs="?", type=int, help="número de la acción en la lista (empieza en 0)")
    parser.add_argument("--aprobador", default="", help="persona que aprueba, p. ej. «N2 - Ana López»")
    parser.add_argument("--motivo", default="")
    parser.add_argument("--registro", action="store_true", help="muestra las acciones ejecutadas hasta ahora")
    args = parser.parse_args()

    if args.registro:
        print(json.dumps(SocClient().registro_contencion(), ensure_ascii=False, indent=2))
        return
    if args.resultado is None:
        parser.error("indica el fichero del triaje o --registro")

    resultado = json.loads(args.resultado.read_text(encoding="utf-8"))
    ticket = resultado.get("ticket") or {}
    acciones = ticket.get("recommended_actions") or resultado.get("politica", {}).get("acciones", [])
    if args.indice is None:
        for i, a in enumerate(acciones):
            print(f"[{i}] {a['action']} → {a['target']} | aprueba: {a.get('aprobador', '?')}"
                  + ("" if a.get("permitida", True) else " | PROHIBIDA"))
        return
    try:
        registros = ejecutar_accion(acciones[args.indice], aprobador=args.aprobador, motivo=args.motivo,
                                    ticket_id=ticket.get("ticket_id", ""))
    except (ErrorContencion, IndexError) as e:
        raise SystemExit(f"No se ejecuta: {e}") from e
    if ticket:
        registrar_en_ticket(ticket, registros)
        args.resultado.write_text(json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")
    for r in registros:
        print(f"✓ {r['action']} {r['target']} — aprobado por {r['approved_by']} — {r['result']}", file=sys.stderr)


if __name__ == "__main__":
    _principal()
