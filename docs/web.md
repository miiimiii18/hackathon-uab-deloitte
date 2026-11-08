# Interfaz web

Web propia para la demo: la cola de alertas en directo, qué consulta la IA, en qué se basa, qué propone, qué decide el código y dónde decide la persona. Código en `src/web/`; tests en `tests/test_web.py`.

**Regla de oro (la misma de `docs/guia-ui.md`):** la web muestra lo que decide el backend, no recalcula nada. Severidad, escalado, permisos y aprobador salen de `src/policy.py`.

## Arrancar

Instalación desde cero en otro ordenador, paso a paso: [`docs/arrancar.md`](arrancar.md).

Dos procesos, desde la raíz del repo y con el entorno activado:

```bash
# 1. API simulada del SOC (déjala abierta)
uvicorn mock_soc_api:app --app-dir data/tarvia/06_herramientas --port 8000

# 2. La web (abre el navegador en http://127.0.0.1:8080)
python -m src.web
```

Variables opcionales: `WEB_PORT` (8080) y `WEB_ABRIR=0` para no abrir el navegador. El LLM se configura como siempre en `.env` (`LLM_API_KEY`, `LLM_MODEL=ornith`...). La cabecera de la web muestra si la API del SOC y la clave del LLM están disponibles.

Solo se usa el LLM de la organización (la clave del equipo en `.env`); nada corre en local. Si `LLM_MODEL` apunta a un modelo que el servidor no tiene (p. ej. `qwen3:8b` de las pruebas con Ollama), la web usa `ornith` y avisa con un banner amarillo para que lo corrijáis en `.env`. Si falta la API del SOC o la clave, el banner rojo dice qué arrancar o qué poner, y ofrece el modo demo.

No hay `npm`, ni build, ni fuentes ni recursos de terceros: todo es estático y funciona sin red (RGPD y plan B).

## Pantallas

| Pantalla | Qué hace |
|---|---|
| **Cola** (`#/`) | Las 10 alertas de la guía (`COLA_INICIAL` en `src/web/api.py`). «Triar las N» las tría en paralelo y cada fila avanza por Evidencia → IA → Política → Persona según el servidor avisa. Filtros por regla, severidad, veredicto y estado (se recuerdan al recargar, solo en esa pestaña). Las alertas triadas que forman un mismo ataque llevan la etiqueta «Mismo ataque · N alertas». |
| **Detalle** (`#/alerta/ID`) | Qué ha consultado (`traza`), en qué se basa (`evidencia`), qué propone la IA (`llm.analisis`), qué decide la política (`politica`) y la decisión de la persona (acciones del ticket). |
| **Informe de investigación** (panel del detalle) | Solo en lo escalado. «Generar informe» pide al servidor el informe del nivel 3 (línea de tiempo con eventos reales, alcance, causa raíz, contención propuesta, a quién avisar...) y lo guarda en `data/out/web/informes/`. |
| **Registro** (`#/registro`) | Acciones ejecutadas en la API simulada (`containment_log`): cuándo, acción, objetivo, ticket, quién aprobó, token de aprobación y resultado. |
| **Cargar alertas** (panel lateral) | Pegar JSON (uno, lista o JSONL), subir `.json`/`.jsonl` o elegir de la muestra del dataset. Solo rechaza una alerta que no trae nada que investigar (ni `rule_id`, ni `rule_name`, ni `entities`, ni `evidence`). Si falta `alert_id` le pone uno estable (`ALR-MANUAL-…`); los demás campos que falten (`severity`, `created_at`, `entities`...) se marcan en amarillo y el servidor los completa del catálogo de reglas o los deja como aviso en el resultado. |

Diseño de «parte de triaje» (tema claro, solo fuentes del sistema, sin recursos externos). Cada rol tiene su voz tipográfica: la IA habla en cursiva serif con ✦, el código en monoespaciada con `{ }` y la persona firma en azul tinta (✍). El color se reserva para la gravedad y para los sellos de la decisión (Escalar · N2, Revisión humana, Cerrar). Cada bloque del detalle lleva el nivel del reto que cubre (N1–N4).

- **Cola:** bandeja de entrada, marcador (triadas, escalar, revisión, cerrar, ataques agrupados) y una fila por alerta con la razón de la IA y su cita, la línea del código, la cuenta de la gravedad, un punto por consulta (rojo malicioso, hueco desconocido, verde limpio) y el sello.
- **Detalle (expediente):** conclusión y «quién decide qué» arriba; a la izquierda, por qué (eventos citados, con los que **no** venían en la alerta en ocre), la cronología, el grafo de implicados, las dudas de la IA, el grupo, el informe N3 y la evidencia completa; a la derecha, qué ha consultado (cascada con tiempos reales), la matriz de gravedad y la contención que firma una persona.

## Modo demo (plan B sin red)

Cada triaje se guarda en `data/out/web/<alert_id>.json`. Con «Modo demo» activado, «Triar» reproduce los resultados guardados (también los de `data/out/demo/`) sin tocar la API del SOC ni el LLM. Antes de la defensa, triar las 10 una vez con red para dejarlas guardadas.

## API (`src/web/api.py`)

| Endpoint | Para qué |
|---|---|
| `GET /api/estado` | API del SOC y LLM disponibles, modelo, paralelismo y la matriz de severidad de `src/policy.py` (la web la dibuja, no tiene copia) |
| `GET /api/cola-inicial`, `GET /api/alertas?q=`, `GET /api/alertas/{id}` | Alertas del dataset |
| `POST /api/triaje` | Tría alertas (IDs o JSON) en paralelo; responde por SSE con `etapa`, `resultado` y `fin` |
| `GET /api/resultados`, `GET /api/resultados/{id}` | Resúmenes y resultado completo de `triar()` |
| `POST /api/resultados/{id}/acciones/{n}/ejecutar` | Ejecuta la acción `n` del ticket (`src/contencion.py`). El servidor toma la acción de su copia del ticket: el navegador no puede cambiar `permitida` |
| `POST /api/resultados/{id}/decisiones` | Anota cerrar, pasar a N2, rechazar una acción o corregir el veredicto/severidad (`corregir`, con nombre y motivo); no recalcula nada |
| `GET /api/registro` | `containment_log` de la API simulada |
| `GET /api/alertas/{id}/original` | La alerta tal como llegó (la del resultado o la del dataset) |
| `POST /api/resultados/{id}/investigar` | Genera el informe del nivel 3 del incidente de esa alerta (del grupo entero si lo hay). 409 si no está escalado |
| `GET /api/resultados/{id}/informe` | El último informe guardado de esa alerta (404 si no hay) |
| `GET /api/grupos` | Alertas triadas del mismo ataque, cada grupo con su ticket único |

La documentación interactiva está en `/api/docs`.

## Seguridad

- El texto de alertas y logs puede escribirlo el atacante: el front construye el DOM solo con `textContent` (`src/web/static/js/dom.js`), nunca con `innerHTML`.
- La contención solo se ejecuta desde un botón, con nombre de quien aprueba cuando la política lo exige. «Mantén pulsado» evita pulsaciones accidentales.
- El servidor escucha solo en `127.0.0.1`.
- Los ficheros del front se sirven con `Cache-Control: no-cache`: tras un `git pull` el navegador no mezcla JS viejo con CSS nuevo. Si alguien abrió la web antes de este cambio, que recargue una vez con Ctrl+Shift+R.
- Antes de la demo, borrar `data/tarvia/06_herramientas/containment_log.jsonl` para empezar con el registro vacío.
