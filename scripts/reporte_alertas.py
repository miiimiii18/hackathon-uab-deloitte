"""Genera el reporte de entrega de un conjunto de alertas a partir de sus resultados de triaje.

Para cada alerta: por qué ha saltado, qué ha investigado el sistema, qué concluye (y quién decide
qué) y qué acciones se proponen o se han tomado (contención, escalado). Todo sale de los resultados
reales guardados por la web en data/out/web/<alert_id>.json: el reporte no inventa ni recalcula nada.

Desde la raíz del proyecto:
    python -m scripts.reporte_alertas demo_alertas_comunes.jsonl
    python -m scripts.reporte_alertas mis_alertas.jsonl --salida REPORTE.md
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from src.agrupar import agrupar_resultados

RESULTADOS = Path("data/out/web")
VEREDICTO = {"true_positive": "Ataque real", "benign_true_positive": "Actividad autorizada",
             "false_positive": "Falsa alarma", "needs_more_info": "Falta información (revisión humana)"}
GRAVEDAD = {"informational": "Informativa", "low": "Baja", "medium": "Media", "high": "Alta", "critical": "Crítica"}
DECISION = {"escalar": "Escalar a N2", "revisar": "Revisión humana", "cerrar": "Cerrar"}
ESTADO_IOC = {"malicious": "maliciosa", "suspicious": "sospechosa", "unknown": "desconocida (no es limpia)", "clean": "limpia"}
ACCION = {"block_ioc": "Bloquear indicadores", "purge_email": "Purgar el correo", "isolate_host": "Aislar el equipo",
          "disable_account": "Deshabilitar la cuenta", "revoke_sessions": "Revocar sesiones", "reset_password": "Forzar cambio de contraseña",
          "disable_access_key": "Desactivar la clave", "close": "Cerrar", "human_review": "Revisión humana"}
TIPOS_CONSULTA = [("/alerts", "alerta"), ("/assets", "inventario de equipos"), ("/users", "directorio de personas"),
                  ("/intel", "inteligencia"), ("/sandbox", "sandbox"), ("/changes", "calendario de cambios"), ("/logs", "registros ±24 h")]


def hora_madrid(iso: str | None) -> str:
    """Hora de España: UTC+2 hasta el 25-oct-2026 (cambio de hora), UTC+1 después."""
    if not iso:
        return "sin hora"
    t = datetime.fromisoformat(iso)
    desfase = 2 if t < datetime(2026, 10, 25, 1, tzinfo=UTC) else 1
    return (t + timedelta(hours=desfase)).strftime("%d/%m/%Y %H:%M") + " (hora de España)"


def texto(valor: Any) -> str:
    """Una sola línea, sin barras verticales que rompan las tablas de Markdown."""
    return " ".join(str(valor or "").split()).replace("|", "/")


def legible(t: str) -> str:
    for k, v in {**VEREDICTO, **GRAVEDAD}.items():
        t = t.replace(k, v.lower())
    return t.replace("severidad", "gravedad")


def consultas(r: dict[str, Any]) -> str:
    traza = r.get("traza") or []
    partes = []
    for prefijo, nombre in TIPOS_CONSULTA:
        n = sum(1 for t in traza if str(t.get("consulta", "")).startswith(prefijo))
        if n:
            partes.append(f"{n} de {nombre}")
    fuentes = sorted({t["consulta"].split("/")[2] for t in traza if str(t.get("consulta", "")).startswith("/logs/")})
    extra = f" (fuentes: {', '.join(fuentes)})" if fuentes else ""
    return f"{len(traza)} consultas a la API del SOC: {', '.join(partes)}{extra}."


def bloque_alerta(n: int, r: dict[str, Any], grupo: dict[str, Any] | None) -> list[str]:
    a, p, t = r["alerta"], r["politica"], r["ticket"]
    ia = r["llm"]["analisis"]
    relacionados = set(a.get("related_events") or [])
    citados = {e.get("event_id") for e in (r["evidencia"].get("eventos_citados_en_la_alerta") or [])}
    citados |= {e.get("event_id") for c in (r["evidencia"].get("contexto_logs") or []) for e in (c.get("muestra") or [])}
    decision = DECISION.get(p["decision"], p["decision"])
    if grupo and p["decision"] != "escalar":
        decision = f"Escalar a N2 con su grupo (sola: {decision.lower()})"

    s = [f"### {n}. {a['alert_id']} — {texto(t.get('title'))}", ""]
    s += [f"**Conclusión: {VEREDICTO.get(p['veredicto'], p['veredicto'])} · gravedad {GRAVEDAD.get(p['severidad_final'], p['severidad_final']).lower()} · {decision}**", ""]

    s += ["**Por qué ha saltado**", "",
          f"- Regla `{a.get('rule_id')}` ({texto(a.get('rule_name'))}) de {a.get('source_product')}, gravedad de la regla {GRAVEDAD.get(a.get('severity'), a.get('severity'))}.",
          f"- {texto(a.get('description'))}",
          f"- Hora de la alerta: {hora_madrid(a.get('created_at'))}.", ""]

    s += ["**Qué se ha investigado**", "", f"- {consultas(r)}"]
    for i in r["evidencia"].get("inteligencia") or []:
        familia = (i.get("tip") or {}).get("malware_family")
        geo = i.get("geo") or {}
        # El origen sale de la GeoIP (dato), no de lo que redacte la IA.
        donde = ", ".join(x for x in [geo.get("city"), geo.get("country"), geo.get("as_org"), "hosting" if str(geo.get("is_hosting")) == "True" else None] if x)
        s.append(f"- Inteligencia de `{texto(i.get('indicador'))[:70]}`: {ESTADO_IOC.get(i.get('estado'), i.get('estado'))}{f' ({familia})' if familia else ''}"
                 f"{f'; GeoIP: {donde}' if donde else ''}.")
    for host, act in (r["evidencia"].get("activos") or {}).items():
        if isinstance(act, dict):
            s.append(f"- Equipo `{host}`: {act.get('type', 'equipo')}, criticidad {str(act.get('criticality', '?')).lower()}.")
        else:
            s.append(f"- Equipo `{host}`: no está en la CMDB (se trata como desconocido).")
    cambios = r["evidencia"].get("cambios_aprobados") or []
    s.append(f"- Calendario de cambios: {', '.join(texto(c.get('id') or c.get('change_id')) for c in cambios) or 'ningún cambio aprobado que lo cubra'}.")
    s.append("")

    s += [f"**Qué concluye la IA** (propone; confianza {ia.get('confidence')})", "", f"> {texto(ia.get('summary'))}", ""]
    pruebas = [e for e in ia.get("evidence") or [] if e.get("event_id") != a["alert_id"]][:6]
    if pruebas:
        s += ["Pruebas que cita:", ""]
        for e in pruebas:
            fuera = e.get("event_id") in citados and relacionados and e.get("event_id") not in relacionados
            cita = f"`{e['event_id']}` " if e.get("event_id") else ""
            s.append(f"- {cita}({e.get('source')}): {texto(e.get('finding'))}{' — *evento que no venía en la alerta*' if fuera else ''}")
        s.append("")

    s += ["**Qué decide el código** (política del SOC, no la IA)", "",
          f"- Gravedad: {legible(texto(p.get('razon_severidad')))}"]
    if p.get("veredicto_llm") != p.get("veredicto"):
        s.append(f"- **El código corrige a la IA:** la IA dijo «{VEREDICTO.get(p['veredicto_llm'])}» y queda «{VEREDICTO.get(p['veredicto'])}».")
    if p.get("autorizacion"):
        s.append(f"- Autorización verificada (fecha y origen): {texto(p['autorizacion'])}.")
    for aviso in p.get("avisos") or []:
        s.append(f"- Aviso: {legible(texto(aviso))}")
    if p.get("motivos_escalado"):
        s.append(f"- Escala porque: {legible(' · '.join(p['motivos_escalado']))}.")
    if grupo:
        s.append(f"- Forma parte del grupo `{grupo['grupo_id']}` ({len(grupo['alert_ids'])} alertas del mismo ataque, unidas por {texto(', '.join(grupo['entidades']))}): ticket único `{grupo['ticket']['ticket_id']}`, que se escala a N2.")
    sla = p.get("sla") or {}
    if sla:
        s.append(f"- Plazo (SLA): triaje en {sla.get('tiempo_triaje')}; {texto(sla.get('escalado'))}; avisar a: {texto(sla.get('notificar'))}.")
    s.append("")

    acciones = [x for x in t.get("recommended_actions") or [] if x.get("action") not in ("close", "human_review")]
    ejecutadas = t.get("executed_actions") or []
    s += ["**Acciones (contención y escalado)**", ""]
    if acciones:
        s += ["| Acción | Objetivo | Quién la aprueba | Estado |", "|---|---|---|---|"]
        for x in acciones:
            hecha = next((e for e in ejecutadas if e.get("action") == x.get("action")), None)
            quien = "Prohibida (red OT: solo se escala)" if not x.get("permitida", True) else (f"Persona: {x.get('aprobador')}" if x.get("requires_approval") else "N1 (sin aprobación previa)")
            estado = f"Ejecutada, aprobó {hecha.get('approved_by')}" if hecha else "Propuesta, pendiente de la persona"
            s.append(f"| {ACCION.get(x['action'], x['action'])} | {texto(x.get('target'))[:110]} | {quien} | {estado} |")
    else:
        s.append("- No se propone contención." if p["decision"] == "cerrar" else "- Sin contención propuesta: la decide la persona tras revisarla.")
    s.append(f"- Escalado: {decision}.")
    s.append("")

    dudas = ia.get("open_questions") or []
    if dudas:
        s += ["**Preguntas abiertas para quien lo revise**", ""] + [f"- {texto(q)}" for q in dudas] + [""]
    return s


def generar(ids: list[str]) -> tuple[str, list[dict[str, Any]]]:
    resultados = {}
    for i in ids:
        ruta = RESULTADOS / f"{i}.json"
        if not ruta.exists():
            raise SystemExit(f"Falta el resultado de {i} en {RESULTADOS}: triad primero las alertas en la web.")
        r = json.loads(ruta.read_text(encoding="utf-8"))
        if "error" in r:
            raise SystemExit(f"El triaje de {i} dio error: {r['error']}. Volved a triarla.")
        resultados[i] = r
    # Grupos con todo lo triado (como en la web): una alerta puede unirse a otras de fuera de las 10.
    todos = {f.stem: json.loads(f.read_text(encoding="utf-8")) for f in RESULTADOS.glob("*.json")}
    todos = {k: v for k, v in todos.items() if "error" not in v and v.get("alerta")}
    grupos = agrupar_resultados(todos, {k: v["alerta"] for k, v in todos.items()})
    grupo_de = {i: g for g in grupos for i in g["alert_ids"]}

    orden = {"escalar": 0, "revisar": 1, "cerrar": 2}
    ids_orden = list(ids)  # en el mismo orden en que vienen en el fichero (el de Deloitte)
    fecha = max(r.get("triado_en", "") for r in resultados.values())[:16].replace("T", " ")
    cuenta = {d: sum(1 for i in ids if (("escalar" if i in grupo_de else resultados[i]["politica"]["decision"]) == d)) for d in orden}

    s = ["# Reporte de triaje · 10 alertas de la demo", "",
         "**Equipo TEMIPO · UAB The Hack 2026 · reto Deloitte**", "",
         (f"Generado automáticamente a partir de los resultados reales del sistema (triaje del {fecha} UTC) con "
          "`python -m scripts.reporte_alertas`. Para cada alerta: por qué ha saltado, qué ha investigado el sistema, "
          "qué propone la IA, qué decide el código y qué acciones se proponen (contención y escalado) y quién las aprueba."), "",
         (f"**Resultado: {cuenta['escalar']} a N2 · {cuenta['revisar']} a revisión humana · {cuenta['cerrar']} cerradas.** "
          "La IA propone el veredicto y lo argumenta; la gravedad, el escalado y los permisos los calcula el código con la política del SOC; "
          "ninguna acción de contención se ejecuta sin una persona."), "",
         "## Resumen", "",
         "| # | Alerta | Qué ha pasado | Veredicto | Gravedad | Decisión |", "|---|---|---|---|---|---|"]
    for n, i in enumerate(ids_orden, 1):
        r = resultados[i]
        p = r["politica"]
        dec = DECISION.get(p["decision"], p["decision"])
        if i in grupo_de and p["decision"] != "escalar":
            dec = "Escalar a N2 (con su grupo)"
        s.append(f"| {n} | `{i}` | {texto(r['ticket'].get('title'))} | {VEREDICTO.get(p['veredicto'])} | {GRAVEDAD.get(p['severidad_final'])} | {dec} |")
    s.append("")
    propios = [g for g in grupos if any(i in g["alert_ids"] for i in ids)]
    if propios:
        s += ["## Alertas del mismo ataque", ""]
        for g in propios:
            dentro = [i for i in g["alert_ids"] if i in ids]
            s.append(f"- `{g['grupo_id']}` · {len(g['alert_ids'])} alertas ({', '.join(f'`{x}`' for x in g['alert_ids'])}) unidas por "
                     f"{texto(', '.join(g['entidades']))}. De estas 10: {', '.join(f'`{x}`' for x in dentro)}. Ticket único `{g['ticket']['ticket_id']}`, "
                     f"gravedad {GRAVEDAD.get(g['severidad'], g['severidad']).lower()}, escalado a N2.")
        s.append("")
    s += ["## Alerta por alerta", ""]
    for n, i in enumerate(ids_orden, 1):
        s += bloque_alerta(n, resultados[i], grupo_de.get(i))
    s += ["---", "", ("Los tickets completos (formato `ticket_salida.schema.json` de Deloitte, validados) están en "
                      "`REPORTE_10_ALERTAS_tickets.json`. Lo que esta solución no resuelve: `docs/limitaciones.md`."), ""]
    return "\n".join(s), [resultados[i]["ticket"] for i in ids_orden]


def main() -> None:
    parser = argparse.ArgumentParser(description="Reporte de entrega de un conjunto de alertas triadas")
    parser.add_argument("alertas", type=Path, help="fichero JSON o JSONL con las alertas (se usan sus alert_id)")
    parser.add_argument("--salida", type=Path, default=Path("REPORTE_10_ALERTAS.md"))
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    contenido = args.alertas.read_text(encoding="utf-8").strip()
    lista = json.loads(contenido) if contenido.startswith("[") else [json.loads(x) for x in contenido.splitlines() if x.strip()]
    informe, tickets = generar([a["alert_id"] for a in lista])
    args.salida.write_text(informe, encoding="utf-8")
    args.salida.with_name(args.salida.stem + "_tickets.json").write_text(json.dumps(tickets, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Reporte en {args.salida} ({len(tickets)} alertas) y tickets en {args.salida.stem}_tickets.json")


if __name__ == "__main__":
    main()
