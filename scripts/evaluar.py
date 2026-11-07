"""Evalúa el triaje contra casos etiquetados a mano (evaluacion/casos.json).

Cada caso dice qué veredictos son aceptables y por qué. El script tría todas las
alertas (en paralelo), compara el veredicto FINAL (el de la política) y muestra el
acierto por categoría. Con --repeticiones N repite cada alerta N veces para medir
la ESTABILIDAD del modelo (en casos límite puede cambiar de una ejecución a otra).

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


def evaluar(casos: list[dict], repeticiones: int, paralelo: int) -> list[dict]:
    # «fichero» = alerta que no está en el dataset (p. ej., las inventadas para la prueba de robustez).
    referencias = [c.get("fichero") or c["alert_id"] for c in casos for _ in range(repeticiones)]
    resultados = triar_lote(referencias, en_paralelo=paralelo)
    filas = []
    for i, caso in enumerate(casos):
        tandas = resultados[i * repeticiones:(i + 1) * repeticiones]
        veredictos = [r.get("politica", {}).get("veredicto", "ERROR: " + r.get("error", "?")) for r in tandas]
        aciertos = sum(v in caso["veredictos_validos"] for v in veredictos)
        filas.append({**caso, "veredictos": veredictos, "aciertos": aciertos, "total": len(veredictos),
                      "estable": len(set(veredictos)) == 1, "resultados": tandas})
    return filas


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
    ok, total = sum(f["aciertos"] for f in filas), sum(f["total"] for f in filas)
    inestables = [f["alert_id"] for f in filas if not f["estable"]]
    lineas.append(f"  {'TOTAL':18} {ok}/{total} ({100 * ok / total:.0f} %)")
    if inestables:
        lineas.append(f"  Inestables (veredicto distinto entre repeticiones): {', '.join(inestables)}")
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
