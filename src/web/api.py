"""Servidor de la interfaz web: expone el triaje del backend y sirve el front estático.

La web solo MUESTRA lo que decide el backend (src/triaje.py, src/policy.py): aquí no se
recalcula severidad, escalado ni permisos. Lo único que añade es el transporte:
- /api/triaje tría alertas en paralelo y va enviando cada etapa por SSE;
- los resultados se guardan en data/out/web/ (memoria + disco), que es también el «modo demo»;
- la contención se ejecuta por el índice de la acción en el ticket guardado en el servidor,
  nunca con una acción que mande el navegador (así `permitida` no se puede manipular).

Arrancar:  python -m src.web      (necesita la API del SOC en SOC_API_URL)
"""

from __future__ import annotations

import json
import logging
import queue
import re
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src import llm
from src.contencion import ErrorContencion, ejecutar_accion, registrar_en_ticket
from src.soc_client import SOC_API_URL, ErrorSOC, SocClient
from src.triaje import MAX_PARALELO, PARALELO, cargar_alerta, triar

RAIZ = Path(__file__).resolve().parents[2]
ESTATICOS = Path(__file__).resolve().parent / "static"
RUTA_ALERTAS = RAIZ / "data/tarvia/03_alertas/alertas.jsonl"
RUTA_MUESTRA = RAIZ / "data/tarvia/03_alertas/alertas_muestra_desarrollo.jsonl"
CARPETAS_RESULTADOS = [RAIZ / "data/out/web", RAIZ / "data/out/demo"]  # la primera es donde se escribe

# Las 10 de la guía de la UI (sección 8): cubren incidente claro, injection, corrección de la IA,
# autorizado, pareja ataque/legítimo, ruido, fraude y una duda.
COLA_INICIAL = [
    "ALR-20261009-011791", "ALR-20261018-011895", "ALR-20261011-011807", "ALR-20261007-001237",
    "ALR-20261020-011905", "ALR-20261008-001417", "ALR-20261008-011833", "ALR-20261005-000301",
    "ALR-20261023-011915", "ALR-20261009-001917",
]
CAMPOS_OBLIGATORIOS = ("alert_id", "rule_id", "severity", "created_at", "entities")
DECISIONES_HUMANAS = {"cerrar", "escalar_n2", "rechazar_accion"}

LOG = logging.getLogger("uvicorn.error")
PULSO = 8  # segundos sin novedades antes de mandar un pulso por el flujo SSE
MODELO_ALTERNATIVO = "ornith"  # el de la organización (CLAUDE.md): se usa si el de .env no existe en el servidor
_VIGENCIA_MODELOS = 60  # segundos que se recuerda la lista de modelos del servidor

app = FastAPI(title="TEMIPO · Triaje N1", docs_url="/api/docs", openapi_url="/api/openapi.json")
_cerrojo = threading.RLock()
_modelos: dict[str, Any] = {"hasta": 0.0, "ids": None}
_indice_cache: dict[Path, dict[str, dict[str, Any]]] = {}
_resultados: dict[str, dict[str, Any]] = {}
_disco_leido = False


# --- Alertas del dataset -------------------------------------------------------------------


def resumen_alerta(alerta: dict[str, Any]) -> dict[str, Any]:
    return {k: alerta.get(k) for k in ("alert_id", "rule_id", "rule_name", "severity", "source_product", "created_at")}


def _indice() -> dict[str, dict[str, Any]]:
    """Resumen de las alertas del dataset por ID (se lee una vez; las 11.061 caben de sobra)."""
    ruta = RUTA_ALERTAS if RUTA_ALERTAS.exists() else RUTA_MUESTRA
    with _cerrojo:
        if ruta not in _indice_cache:
            indice: dict[str, dict[str, Any]] = {}
            if ruta.exists():
                with ruta.open(encoding="utf-8") as f:
                    for linea in f:
                        if linea.strip():
                            a = json.loads(linea)
                            indice[a["alert_id"]] = resumen_alerta(a)
            _indice_cache[ruta] = indice
        return _indice_cache[ruta]


def _ids_muestra() -> list[str]:
    if not RUTA_MUESTRA.exists():
        return []
    with RUTA_MUESTRA.open(encoding="utf-8") as f:
        return [json.loads(linea)["alert_id"] for linea in f if linea.strip()]


def faltan_campos(alerta: Any) -> list[str]:
    if not isinstance(alerta, dict):
        return list(CAMPOS_OBLIGATORIOS)
    return [c for c in CAMPOS_OBLIGATORIOS if alerta.get(c) in (None, "", {}, [])]


# --- Resultados guardados ------------------------------------------------------------------


def _nombre_seguro(alert_id: str) -> str:
    seguro = re.sub(r"[^\w.-]", "_", str(alert_id))[:120].strip(".")
    if not seguro:
        raise HTTPException(400, "ID de alerta no válido")
    return seguro


def _leer_disco() -> None:
    global _disco_leido
    with _cerrojo:
        if _disco_leido:
            return
        for carpeta in reversed(CARPETAS_RESULTADOS):  # lo de web/ pisa a lo de demo/
            for fichero in sorted(carpeta.glob("*.json")) if carpeta.exists() else []:
                try:
                    r = json.loads(fichero.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if isinstance(r, dict) and r.get("alert_id") and "error" not in r:
                    _resultados[r["alert_id"]] = r
        _disco_leido = True


def _guardar(resultado: dict[str, Any]) -> None:
    alert_id = resultado.get("alert_id")
    if not alert_id or "error" in resultado:
        return
    with _cerrojo:
        _resultados[alert_id] = resultado
        carpeta = CARPETAS_RESULTADOS[0]
        carpeta.mkdir(parents=True, exist_ok=True)
        destino = carpeta / f"{_nombre_seguro(alert_id)}.json"
        temporal = destino.with_suffix(".tmp")  # se escribe aparte y se renombra: nunca queda un .json a medias
        temporal.write_text(json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")
        temporal.replace(destino)


def _obtener(alert_id: str) -> dict[str, Any]:
    _leer_disco()
    with _cerrojo:
        r = _resultados.get(alert_id)
    if r is None:
        raise HTTPException(404, f"No hay resultado guardado para {alert_id}")
    return r


def resumen_resultado(r: dict[str, Any]) -> dict[str, Any]:
    """Lo mínimo que necesita la cola; el detalle completo se pide aparte."""
    base = {"alert_id": r.get("alert_id"), "meta": r.get("meta") or _indice().get(r.get("alert_id", "")),
            "triado_en": r.get("triado_en")}
    if "error" in r:
        return {**base, "error": r["error"], "segundos": r.get("segundos_total")}
    t, p = r.get("ticket") or {}, r.get("politica") or {}
    humano = r.get("humano") or []
    return {
        **base,
        "titulo": t.get("title"),
        "veredicto": p.get("veredicto"),
        "veredicto_llm": p.get("veredicto_llm"),
        "severidad": p.get("severidad_final"),
        "decision": p.get("decision"),
        "confianza": t.get("confidence"),
        "segundos": t.get("triage_seconds") or r.get("segundos_total"),
        "acciones_ejecutadas": len(t.get("executed_actions") or []),
        "resuelta": any(h.get("tipo") in ("cerrar", "escalar_n2") for h in humano),
    }


# --- Estado y consulta ---------------------------------------------------------------------


def _soc_responde() -> bool:
    try:
        return requests.get(f"{SOC_API_URL}/alerts", params={"limit": 1}, timeout=2).ok
    except requests.RequestException:
        return False


def _modelos_disponibles() -> list[str] | None:
    """Modelos que ofrece el servidor del LLM; None si no se puede saber (sin clave o sin /models)."""
    with _cerrojo:
        if time.monotonic() < _modelos["hasta"]:
            return _modelos["ids"]
    ids = None
    if llm.API_KEY:
        try:
            r = requests.get(f"{llm.BASE_URL}/models", headers={"Authorization": f"Bearer {llm.API_KEY}"}, timeout=3)
            if r.ok:
                ids = [m["id"] for m in r.json()["data"]]
        except (requests.RequestException, ValueError, KeyError, TypeError):
            ids = None  # el servidor no lista modelos: se deja el configurado y que falle con su propio mensaje
    with _cerrojo:
        _modelos.update(hasta=time.monotonic() + _VIGENCIA_MODELOS, ids=ids)
    return ids


def modelo_efectivo() -> str:
    """El modelo de .env; si el servidor no lo tiene pero sí tiene el de la organización, ese."""
    configurado = llm.MODELO_POR_DEFECTO
    ids = _modelos_disponibles()
    if ids and configurado not in ids and MODELO_ALTERNATIVO in ids:
        return MODELO_ALTERNATIVO
    return configurado


def _aviso_llm() -> str:
    if not llm.API_KEY:
        return "Falta LLM_API_KEY en .env"
    configurado, efectivo, ids = llm.MODELO_POR_DEFECTO, modelo_efectivo(), _modelos_disponibles()
    if efectivo != configurado:
        return f"Tu .env pide «{configurado}», que no existe en el servidor: se usa «{efectivo}». Pon LLM_MODEL={efectivo} en .env."
    if ids is not None and configurado not in ids:
        return f"El modelo «{configurado}» no existe en el servidor (hay: {', '.join(ids) or 'ninguno'}). Revisa LLM_MODEL en .env."
    return ""


@app.get("/api/estado")
def estado() -> dict[str, Any]:
    _leer_disco()
    modelo, ids = modelo_efectivo(), _modelos_disponibles()
    return {
        "soc": _soc_responde(),
        "soc_url": SOC_API_URL,
        "llm": bool(llm.API_KEY) and (ids is None or modelo in ids),
        "llm_aviso": _aviso_llm(),
        "modelo": modelo,
        "paralelo": PARALELO,
        "max_paralelo": MAX_PARALELO,
        "guardados": len(_resultados),
        "dataset": bool(_indice()),
    }


@app.get("/api/cola-inicial")
def cola_inicial() -> list[dict[str, Any]]:
    indice = _indice()
    return [indice.get(i) or {"alert_id": i} for i in COLA_INICIAL]


@app.get("/api/alertas")
def buscar_alertas(q: str = "", limite: int = 40) -> list[dict[str, Any]]:
    """Busca en la muestra de desarrollo (150 alertas variadas) por ID, regla o producto."""
    indice = _indice()
    ids = _ids_muestra() or list(indice)
    texto = q.strip().lower()
    salida = []
    for i in ids:
        a = indice.get(i)
        if a and (not texto or texto in " ".join(str(v) for v in a.values()).lower()):
            salida.append(a)
        if len(salida) >= max(1, min(limite, 200)):
            break
    return salida


@app.get("/api/alertas/{alert_id}")
def ver_alerta(alert_id: str) -> dict[str, Any]:
    a = _indice().get(alert_id)
    if a is None:
        raise HTTPException(404, f"La alerta {alert_id} no está en el dataset")
    return a


@app.get("/api/resultados")
def listar_resultados() -> list[dict[str, Any]]:
    _leer_disco()
    with _cerrojo:
        return [resumen_resultado(r) for r in _resultados.values()]


@app.get("/api/resultados/{alert_id}")
def ver_resultado(alert_id: str) -> dict[str, Any]:
    return _obtener(alert_id)


@app.get("/api/registro")
def registro_contencion() -> list[dict[str, Any]]:
    try:
        return SocClient().registro_contencion()
    except ErrorSOC as e:
        raise HTTPException(502, str(e)) from e


# --- Triaje en directo (SSE) ---------------------------------------------------------------


class PeticionTriaje(BaseModel):
    alertas: list[str | dict[str, Any]]
    paralelo: int = PARALELO
    demo: bool = False


def _sse(evento: dict[str, Any]) -> str:
    return f"data: {json.dumps(evento, ensure_ascii=False)}\n\n"


def _trabajo(i: int, referencia: str | dict[str, Any], salida: queue.Queue) -> None:
    """Tría una alerta con su propio cliente y avisa de cada etapa. Siempre acaba con un resultado."""
    inicio = time.perf_counter()
    nombre = referencia.get("alert_id", "?") if isinstance(referencia, dict) else referencia

    def etapa(nombre_etapa: str) -> None:
        salida.put({"tipo": "etapa", "posicion": i, "alert_id": nombre, "etapa": nombre_etapa})

    try:
        cliente = SocClient()
        alerta = referencia if isinstance(referencia, dict) else cargar_alerta(referencia, cliente)
        nombre = alerta.get("alert_id", nombre)
        etapa("evidencia")

        modelo = modelo_efectivo()

        def enviar(peticion: dict[str, Any]) -> dict[str, Any]:
            etapa("ia")
            respuesta = llm.llamar_api({**peticion, "model": modelo})
            etapa("politica")
            return respuesta

        resultado = triar(alerta, cliente=cliente, enviar=enviar)
        resultado["meta"] = resumen_alerta(alerta)
        if modelo != llm.MODELO_POR_DEFECTO and "llm" in resultado:  # que el resultado diga el modelo que respondió
            resultado["llm"]["modelo"] = modelo
            resultado["ticket"]["modelo"] = modelo
    except Exception as e:  # noqa: BLE001 — el fallo de una alerta se muestra en su fila y no para el lote
        resultado = {"alert_id": nombre, "error": f"{type(e).__name__}: {e}"}
    resultado["segundos_total"] = round(time.perf_counter() - inicio, 1)
    resultado["triado_en"] = datetime.now(UTC).isoformat(timespec="milliseconds")
    try:
        _guardar(resultado)
    except (OSError, HTTPException, TypeError, ValueError) as e:
        resultado["aviso_guardado"] = f"No se pudo guardar el resultado en disco: {e}"
        with _cerrojo:
            _resultados[str(nombre)] = resultado
    try:
        resumen = resumen_resultado(resultado)
    except Exception as e:  # pase lo que pase, la fila de la cola recibe su resultado
        LOG.exception("No se pudo resumir el resultado de %s", nombre)
        resumen = {"alert_id": nombre, "error": f"{type(e).__name__}: {e}"}
    salida.put({"tipo": "resultado", "posicion": i, "alert_id": nombre, "resumen": resumen})


def _trabajo_demo(i: int, referencia: str | dict[str, Any], salida: queue.Queue) -> None:
    """Modo demo: reproduce el recorrido con un resultado guardado, sin tocar la API ni el LLM."""
    nombre = referencia.get("alert_id", "?") if isinstance(referencia, dict) else referencia
    for etapa in ("evidencia", "ia", "politica"):
        salida.put({"tipo": "etapa", "posicion": i, "alert_id": nombre, "etapa": etapa})
        time.sleep(0.5 + 0.15 * (i % 4))
    try:
        resumen = resumen_resultado(_obtener(nombre))
    except HTTPException as e:
        resumen = {"alert_id": nombre, "error": e.detail}
    salida.put({"tipo": "resultado", "posicion": i, "alert_id": nombre, "resumen": resumen})


def _flujo(referencias: list[str | dict[str, Any]], paralelo: int, demo: bool) -> Iterator[str]:
    salida: queue.Queue = queue.Queue()
    hilos = max(1, min(paralelo, MAX_PARALELO, len(referencias)))
    ejecutor = ThreadPoolExecutor(max_workers=hilos)
    inicio = time.perf_counter()
    yield _sse({"tipo": "inicio", "total": len(referencias), "paralelo": hilos})
    try:
        for i, ref in enumerate(referencias):
            ejecutor.submit(_trabajo_demo if demo else _trabajo, i, ref, salida)
        pendientes = len(referencias)
        while pendientes:
            try:
                evento = salida.get(timeout=PULSO)
            except queue.Empty:
                yield ": pulso\n\n"  # comentario SSE: evita que algo por el camino corte una conexión en silencio
                continue
            if evento["tipo"] == "resultado":
                pendientes -= 1
            yield _sse(evento)
        yield _sse({"tipo": "fin", "segundos": round(time.perf_counter() - inicio, 1)})
    except Exception as e:  # se avisa al navegador en vez de cortar la conexión sin explicación
        LOG.exception("Fallo en el flujo de triaje")
        yield _sse({"tipo": "error", "mensaje": f"{type(e).__name__}: {e}"})
    finally:
        ejecutor.shutdown(wait=False, cancel_futures=True)


@app.post("/api/triaje")
def triaje(peticion: PeticionTriaje) -> StreamingResponse:
    if not peticion.alertas:
        raise HTTPException(422, "No hay alertas que triar")
    for ref in peticion.alertas:
        if isinstance(ref, dict) and (faltan := faltan_campos(ref)):
            raise HTTPException(422, f"A la alerta {ref.get('alert_id', '(sin alert_id)')} le faltan campos: {', '.join(faltan)}")
        if isinstance(ref, str) and ref.lower().endswith(".json"):
            raise HTTPException(422, "Se aceptan IDs del dataset o alertas en JSON, no rutas a ficheros")
    return StreamingResponse(
        _flujo(peticion.alertas, peticion.paralelo, peticion.demo),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --- Decisión de la persona ----------------------------------------------------------------


class PeticionAccion(BaseModel):
    aprobador: str = ""
    motivo: str = ""


class PeticionDecision(BaseModel):
    tipo: str
    por: str = ""
    indice: int | None = None
    motivo: str = ""


@app.post("/api/resultados/{alert_id}/acciones/{indice}/ejecutar")
def ejecutar(alert_id: str, indice: int, peticion: PeticionAccion) -> dict[str, Any]:
    """Ejecuta una acción de contención del ticket. El objetivo y los permisos salen del servidor."""
    resultado = _obtener(alert_id)
    ticket = resultado.get("ticket") or {}
    acciones = ticket.get("recommended_actions") or []
    if not 0 <= indice < len(acciones):
        raise HTTPException(404, "Esa acción no existe")
    accion = acciones[indice]
    with _cerrojo:
        if any(e.get("action") == accion.get("action") and e.get("target") in str(accion.get("target"))
               for e in ticket.get("executed_actions") or []):
            raise HTTPException(409, "Esta acción ya se ejecutó")
        try:
            registros = ejecutar_accion(accion, aprobador=peticion.aprobador, motivo=peticion.motivo,
                                        ticket_id=ticket.get("ticket_id", ""))
        except ErrorContencion as e:
            raise HTTPException(400, str(e)) from e
        registrar_en_ticket(ticket, registros)
        _guardar(resultado)
    return {"registros": registros, "executed_actions": ticket["executed_actions"]}


@app.post("/api/resultados/{alert_id}/decisiones")
def decidir(alert_id: str, peticion: PeticionDecision) -> dict[str, Any]:
    """Anota lo que decide la persona (cerrar, pasar a N2, rechazar una acción)."""
    if peticion.tipo not in DECISIONES_HUMANAS:
        raise HTTPException(422, f"Decisión desconocida: {peticion.tipo}")
    if peticion.tipo in ("cerrar", "escalar_n2") and not peticion.por.strip():
        raise HTTPException(400, "Indica el nombre de la persona que decide")
    resultado = _obtener(alert_id)
    with _cerrojo:
        resultado.setdefault("humano", []).append({
            "tipo": peticion.tipo, "por": peticion.por.strip(), "indice": peticion.indice,
            "motivo": peticion.motivo, "cuando": datetime.now(UTC).isoformat(timespec="seconds"),
        })
        _guardar(resultado)
    return {"humano": resultado["humano"]}


class Estaticos(StaticFiles):
    """En Windows el registro del sistema a veces da text/plain a los .js y el navegador se niega
    a cargarlos como módulos: se fuerza el tipo correcto."""

    async def get_response(self, path: str, scope):
        respuesta = await super().get_response(path, scope)
        if path.endswith(".js"):
            respuesta.headers["content-type"] = "text/javascript; charset=utf-8"
        return respuesta


# El front va al final: las rutas /api tienen prioridad.
app.mount("/", Estaticos(directory=ESTATICOS, html=True), name="web")
