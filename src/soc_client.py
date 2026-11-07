"""Cliente de la API simulada del SOC de Tarvia.

La API la da Deloitte (data/tarvia/06_herramientas/mock_soc_api.py). Este cliente:
- Envuelve cada endpoint en un método con nombre claro (activo, usuario, intel...).
- Trata un 404 como un DATO ("desconocido"), no como un error: devuelve None.
- Guarda cada consulta en `traza` (qué se consultó, cuántos resultados, cuánto tardó)
  para enseñarla en la UI: «qué consulta el sistema y en qué se basa».
- Cachea las respuestas: la misma consulta no se repite.
- Filtra los logs por coincidencia EXACTA: la API busca por subcadena y, por ejemplo,
  `q=10.10.1.1` también devolvería eventos de `10.10.1.185`.

Para arrancar la API (desde la raíz del proyecto):
    uvicorn mock_soc_api:app --app-dir data/tarvia/06_herramientas --port 8000
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import requests
from dotenv import load_dotenv

load_dotenv()

# 127.0.0.1 y no «localhost»: en Windows, «localhost» prueba primero IPv6 (::1), la
# API solo escucha en IPv4 y cada petición pierde ~2 s esperando el fallo.
SOC_API_URL = os.getenv("SOC_API_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT = float(os.getenv("SOC_API_TIMEOUT", "120"))

# Prefijo del event_id → fichero de log donde está ese evento.
FUENTE_POR_PREFIJO = {
    "ADE": "ad_events",
    "AIG": "ai_gateway",
    "AUD": "idp_audit",
    "CI": "cicd_builds",
    "CLK": "email_clicks",
    "CT": "cloudtrail",
    "DLP": "dlp",
    "DNS": "dns",
    "ECA": "ecom_auth",
    "ECO": "ecom_account",
    "EDR": "edr_events",
    "EML": "email",
    "FW": "firewall",
    "PRX": "proxy",
    "SIGN": "idp_signins",
    "SQL": "sql_audit",
    "VPN": "vpn",
    "WAF": "waf",
}

FORMATO_FECHA = "%Y-%m-%dT%H:%M:%S.000Z"


class ErrorSOC(Exception):
    """La API del SOC no responde o devuelve un error inesperado."""


# Una función que recibe (ruta, parámetros) y devuelve (código HTTP, cuerpo).
# Los tests la sustituyen por una falsa para no necesitar la API.
Obtener = Callable[[str, dict[str, Any]], tuple[int, Any]]


def _obtener_http(base_url: str, timeout: float) -> Obtener:
    def obtener(ruta: str, params: dict[str, Any]) -> tuple[int, Any]:
        try:
            r = requests.get(base_url + ruta, params=params, timeout=timeout)
        except requests.ConnectionError as e:
            raise ErrorSOC(
                f"No hay conexión con la API del SOC en {base_url}. ¿Está arrancada (uvicorn)?"
            ) from e
        except requests.Timeout as e:
            raise ErrorSOC(f"La API del SOC tardó más de {timeout:.0f} s en {ruta}") from e
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text

    return obtener


# --- Utilidades ---------------------------------------------------------------------


def a_fecha(texto: str) -> datetime | None:
    """Convierte '2026-10-05T07:56:30.000Z' en datetime (UTC). None si no se puede."""
    try:
        return datetime.fromisoformat(texto)  # desde Python 3.11 entiende la «Z» final
    except (AttributeError, ValueError):
        return None


def ventana(momento: str, horas: int = 24) -> tuple[str, str]:
    """Devuelve (desde, hasta) = momento ± horas, en el formato de fecha de los logs."""
    centro = a_fecha(momento)
    if centro is None:
        raise ValueError(f"Fecha no válida: {momento!r}")
    centro = centro.astimezone(UTC)
    delta = timedelta(hours=horas)
    return (centro - delta).strftime(FORMATO_FECHA), (centro + delta).strftime(FORMATO_FECHA)


def _textos(valor: Any) -> Iterator[str]:
    """Recorre todos los textos de un evento, incluidos los anidados."""
    if isinstance(valor, str):
        yield valor
    elif isinstance(valor, dict):
        for v in valor.values():
            yield from _textos(v)
    elif isinstance(valor, list):
        for v in valor:
            yield from _textos(v)


def coincide_exacto(evento: dict[str, Any], termino: str, *, subdominios: bool = False) -> bool:
    """¿Aparece `termino` en el evento como valor completo y no como trozo de otro?

    `10.10.1.1` no coincide con `10.10.1.185`, ni `carmen.serra` con `carmen.serra2`.
    Sí coincide `sergi.rubio` con `TARVIA\\sergi.rubio` o `sergi.rubio@tarvia.example`.
    Con subdominios=True, `wetransfer.com` también coincide con `www.wetransfer.com`.
    """
    antes = r"(?<![\w-])" if subdominios else r"(?<![\w.-])"
    patron = re.compile(antes + re.escape(termino) + r"(?![\w-]|\.\w)", re.IGNORECASE)
    return any(patron.search(t) for t in _textos(evento))


def _contar(cuerpo: Any) -> int:
    if cuerpo is None:
        return 0
    if isinstance(cuerpo, dict) and "count" in cuerpo:
        return cuerpo["count"]
    if isinstance(cuerpo, list):
        return len(cuerpo)
    return 1


# --- Cliente ------------------------------------------------------------------------


class SocClient:
    def __init__(
        self,
        base_url: str = SOC_API_URL,
        *,
        obtener: Obtener | None = None,
        timeout: float = TIMEOUT,
    ):
        self.base_url = base_url
        self._obtener = obtener or _obtener_http(base_url, timeout)
        self._cache: dict[tuple, Any] = {}
        self.traza: list[dict[str, Any]] = []

    def _get(self, ruta: str, params: dict[str, Any] | None = None) -> Any | None:
        params = {k: v for k, v in (params or {}).items() if v not in (None, "")}
        clave = (ruta, tuple(sorted(params.items())))
        if clave in self._cache:
            resultado = self._cache[clave]
            self.traza.append(
                {"consulta": ruta, "parametros": params, "resultados": _contar(resultado),
                 "ms": 0, "cache": True}
            )
            return resultado

        inicio = time.perf_counter()
        estado, cuerpo = self._obtener(ruta, params)
        ms = round((time.perf_counter() - inicio) * 1000)
        if estado == 404:
            resultado = None  # desconocido: es un dato, no un error
        elif estado != 200:
            raise ErrorSOC(f"La API del SOC respondió {estado} en {ruta}: {str(cuerpo)[:200]}")
        else:
            resultado = cuerpo
        self.traza.append(
            {"consulta": ruta, "parametros": params, "resultados": _contar(resultado),
             "ms": ms, "cache": False, **({"desconocido": True} if estado == 404 else {})}
        )
        self._cache[clave] = resultado
        return resultado

    @staticmethod
    def _ruta(valor: str) -> str:
        return quote(valor, safe="@")

    # Consultas de un elemento. None = no existe / desconocido.

    def alerta(self, alert_id: str) -> dict | None:
        return self._get(f"/alerts/{self._ruta(alert_id)}")

    def activo(self, host_o_ip: str) -> dict | None:
        return self._get(f"/assets/{self._ruta(host_o_ip)}")

    def usuario(self, upn_o_username: str) -> dict | None:
        return self._get(f"/users/{self._ruta(upn_o_username)}")

    def intel(self, indicador: str) -> dict | None:
        return self._get(f"/intel/{self._ruta(indicador)}")

    def sandbox(self, sha256: str) -> dict | None:
        return self._get(f"/sandbox/{self._ruta(sha256)}")

    # Búsquedas.

    def cambios(self, texto: str) -> list[dict]:
        return self._get("/changes", {"q": texto}) or []

    def logs(
        self,
        fuente: str,
        termino: str,
        desde: str | None = None,
        hasta: str | None = None,
        *,
        limite: int = 200,
        subdominios: bool = False,
    ) -> dict[str, Any]:
        """Eventos de `fuente` que contienen `termino` (coincidencia exacta) en [desde, hasta].

        Devuelve {"total": n, "truncado": bool, "eventos": [...]}. «truncado» significa
        que la API cortó en `limite` resultados y puede haber más.
        """
        r = self._get(
            f"/logs/{fuente}", {"q": termino, "desde": desde, "hasta": hasta, "limit": limite}
        )
        if not r:
            return {"total": 0, "truncado": False, "eventos": []}
        eventos = [e for e in r["items"] if coincide_exacto(e, termino, subdominios=subdominios)]
        return {"total": len(eventos), "truncado": bool(r.get("truncated")), "eventos": eventos}

    def evento(self, event_id: str, desde: str | None = None, hasta: str | None = None) -> dict | None:
        """Busca un evento por su ID (p. ej., EDR-0005329) en el log que le corresponde.

        Con una ventana de tiempo la búsqueda es mucho más rápida: la API solo compara
        el texto de los eventos que caen dentro de [desde, hasta].
        """
        fuente = FUENTE_POR_PREFIJO.get(event_id.split("-")[0])
        if fuente is None:
            return None
        r = self._get(f"/logs/{fuente}", {"q": event_id, "desde": desde, "hasta": hasta, "limit": 5})
        for e in (r or {}).get("items", []):
            if e.get("event_id") == event_id:
                return {"fuente": fuente, **e}
        return None
