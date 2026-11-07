"""Prepara el plan B de la demo: tría por la web las alertas de la cola y deja los resultados guardados.

Los resultados van a data/out/web/ (ignorada por git), que es lo que reproduce el «Modo demo»: por eso
hay que ejecutar esto en cada ordenador antes de la defensa. Necesita la API del SOC, la web y la
clave del LLM en marcha (ver docs/web.md). Desde la raíz del proyecto:

    python -m scripts.preparar_demo              # las 10 de la cola + 5 del incidente de phishing de SSO
    python -m scripts.preparar_demo --informe    # además, genera el informe de investigación (nivel 3) de ese incidente
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import requests

from src.web.api import COLA_INICIAL

# Cinco alertas de un mismo ataque (phishing de SSO → toma de cuenta → fraude de IBAN): se agrupan en un ticket.
INCIDENTE_SSO = ["ALR-20261007-011785", "ALR-20261007-011786", "ALR-20261007-011787",
                 "ALR-20261007-011788", "ALR-20261008-011789"]


def triar(base: str, alertas: list[str], paralelo: int) -> dict[str, dict]:
    resumenes: dict[str, dict] = {}
    with requests.post(f"{base}/api/triaje", json={"alertas": alertas, "paralelo": paralelo}, stream=True, timeout=900) as r:
        r.raise_for_status()
        for linea in r.iter_lines(decode_unicode=True):
            if linea and linea.startswith("data: "):
                evento = json.loads(linea[6:])
                if evento["tipo"] == "error":
                    sys.exit(evento["mensaje"])
                if evento["tipo"] == "resultado":
                    resumenes[evento["alert_id"]] = evento["resumen"]
    return resumenes


def main() -> None:
    parser = argparse.ArgumentParser(description="Tría las alertas de la demo y deja los resultados guardados")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--paralelo", type=int, default=5)
    parser.add_argument("--informe", action="store_true", help="genera también el informe de investigación del incidente de SSO")
    args = parser.parse_args()

    inicio = time.perf_counter()
    resumenes = triar(args.url, COLA_INICIAL + INCIDENTE_SSO, args.paralelo)
    for alert_id, r in resumenes.items():
        if "error" in r:
            print(f"  {alert_id}: ERROR {r['error']}")
        else:
            print(f"  {alert_id}: {r['veredicto']:22} {r['severidad']:13} {r['decision']}")
    print(f"{len(resumenes)} alertas en {time.perf_counter() - inicio:.0f} s")

    if args.informe:
        r = requests.post(f"{args.url}/api/resultados/{INCIDENTE_SSO[1]}/investigar", timeout=300)
        print("Informe de investigación:", "guardado" if r.ok else f"error {r.status_code}: {r.text[:200]}")


if __name__ == "__main__":
    main()
