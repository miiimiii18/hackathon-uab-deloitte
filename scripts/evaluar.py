"""Evalúa el triaje contra casos etiquetados a mano (evaluacion/casos.json).

Cada caso dice qué veredictos son aceptables y por qué. El script tría todas las
alertas (en paralelo), compara el veredicto FINAL (el de la política) y muestra el
acierto por categoría. También mide la severidad final y la decisión (cerrar / revisar /
escalar) en los casos que las tienen etiquetadas (`severidades_validas`,
`decisiones_validas`); los demás no cuentan. Con --repeticiones N repite cada alerta N veces
para medir la ESTABILIDAD del modelo (en casos límite puede cambiar de una ejecución a otra).

Necesita la API del SOC arrancada y LLM_API_KEY en .env. Desde la raíz del proyecto
(con -m, para que Python encuentre el paquete src):
    python -m scripts.evaluar
    python -m scripts.evaluar evaluacion/casos.json --repeticiones 3 --paralelo 6
"""

from __future__ import annotations

import argparse
import collections
import json
import time
from pathlib import Path

from src.triaje import triar_lote

METRICAS = (("veredicto", "veredictos_validos"), ("severidad", "severidades_validas"), ("decision", "decisiones_validas"))


def observado(resultado: dict) -> dict[str, str]:
    """Lo que decidió el sistema (veredicto, severidad y decisión finales, los de la política)."""
    p = resultado.get("politica") or {}
    if not p:
        error = "ERROR: " + str(resultado.get("error", "?"))
        return {"veredicto": error, "severidad": error, "decision": error}
    return {"veredicto": p["veredicto"], "severidad": p["severidad_final"], "decision": p["decision"]}


def puntuar(caso: dict, resultado: dict) -> dict[str, bool | None]:
    """Acierta o falla cada métrica. None = el caso no tiene etiqueta para esa métrica (no se mide)."""
    obtenido = observado(resultado)
    return {m: (obtenido[m] in caso[campo] if campo in caso else None) for m, campo in METRICAS}


def evaluar(casos: list[dict], repeticiones: int, paralelo: int) -> list[dict]:
    # «fichero» = alerta que no está en el dataset (p. ej., las inventadas para la prueba de robustez).
    referencias = [c.get("fichero") or c["alert_id"] for c in casos for _ in range(repeticiones)]
    resultados = triar_lote(referencias, en_paralelo=paralelo)
    filas = []
    for i, caso in enumerate(casos):
        tandas = resultados[i * repeticiones:(i + 1) * repeticiones]
        obtenidos = [observado(r) for r in tandas]
        puntos = [puntuar(caso, r) for r in tandas]
        veredictos = [o["veredicto"] for o in obtenidos]
        filas.append({**caso, "veredictos": veredictos, "obtenidos": obtenidos, "puntos": puntos,
                      "aciertos": sum(p["veredicto"] for p in puntos), "total": len(veredictos),
                      "estable": len(set(veredictos)) == 1, "resultados": tandas})
    return filas


def _resumen(filas: list[dict], metrica: str) -> tuple[int, int]:
    medidos = [p[metrica] for f in filas for p in f["puntos"] if p[metrica] is not None]
    return sum(medidos), len(medidos)


def fallos(filas: list[dict]) -> list[str]:
    """Cada fallo, con lo esperado y lo obtenido, para anotar los fallos tipo."""
    lineas = []
    for f in filas:
        for metrica, campo in METRICAS:
            malos = [o[metrica] for o, p in zip(f["obtenidos"], f["puntos"], strict=True) if p[metrica] is False]
            if malos:
                lineas.append(f"  {f['alert_id']:22} {f['categoria']:16} {metrica:9} esperado {' | '.join(f[campo])}"
                              f" → obtenido {', '.join(malos)}")
    return lineas


def informe(filas: list[dict]) -> str:
    lineas = [f"{'alerta':22} {'categoría':18} {'aciertos':>8}  veredictos obtenidos  (válidos)"]
    for f in filas:
        marca = "✅" if f["aciertos"] == f["total"] else ("🟡" if f["aciertos"] else "❌")
        lineas.append(f"{f['alert_id']:22} {f['categoria']:18} {f['aciertos']:>3}/{f['total']:<4} {marca} "
                      f"{', '.join(f['veredictos'])}  ({' | '.join(f['veredictos_validos'])})")
    por_categoria: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    for f in filas:
        por_categoria[f["categoria"]][0] += f["aciertos"]
        por_categoria[f["categoria"]][1] += f["total"]
    lineas.append("")
    for cat, (ok, total) in sorted(por_categoria.items()):
        lineas.append(f"  {cat:18} {ok}/{total} ({100 * ok / total:.0f} %)")
    lineas.append("")
    for metrica, _ in METRICAS:
        ok, total = _resumen(filas, metrica)
        if total:
            lineas.append(f"  {metrica.upper():10} {ok}/{total} ({100 * ok / total:.0f} %)")
    inestables = [f["alert_id"] for f in filas if not f["estable"]]
    if inestables:
        lineas.append(f"  Inestables (veredicto distinto entre repeticiones): {', '.join(inestables)}")
    if lista := fallos(filas):
        lineas += ["", "Fallos (esperado → obtenido):", *lista]
    return "\n".join(lineas)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evalúa el triaje contra casos etiquetados")
    parser.add_argument("casos", nargs="?", type=Path, default=Path("evaluacion/casos.json"))
    parser.add_argument("--repeticiones", type=int, default=1)
    parser.add_argument("--paralelo", type=int, default=6)
    parser.add_argument("--salida", type=Path, default=Path("data/out/evaluacion"))
    args = parser.parse_args()

    casos = json.loads(args.casos.read_text(encoding="utf-8"))
    inicio = time.perf_counter()
    filas = evaluar(casos, args.repeticiones, args.paralelo)
    texto = informe(filas)
    print(texto)
    print(f"\n{len(casos)} casos × {args.repeticiones} en {time.perf_counter() - inicio:.0f} s")

    args.salida.mkdir(parents=True, exist_ok=True)
    marca = time.strftime("%Y%m%d-%H%M%S")
    (args.salida / f"evaluacion-{marca}.json").write_text(json.dumps(filas, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.salida / f"evaluacion-{marca}.txt").write_text(texto, encoding="utf-8")
    print(f"Resultados guardados en {args.salida}/evaluacion-{marca}.*")


if __name__ == "__main__":
    main()
