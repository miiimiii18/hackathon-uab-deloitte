# Guía para construir la interfaz (Streamlit)

Guía para quien haga la UI (Pol) **y para su Claude**. El backend del triaje ya está hecho y probado; esta guía explica cómo usarlo desde Streamlit sin tocarlo. Lee también `CLAUDE.md` (reglas del repo, principios de diseño y briefing del reto).

> **Regla de oro:** la UI **muestra** lo que decide el backend; **no recalcula nada**. La severidad, el veredicto final, el escalado y quién aprueba cada acción ya vienen calculados en `politica` / `ticket`. Si la UI necesita un dato que no está, se añade en el backend (en otra rama), no en la UI.

---

## 1. Qué tiene que enseñar la UI (lo que evalúa Deloitte)

Del README y la presentación de Deloitte, la **demo visual es obligatoria** y debe enseñar:

| Lo que pide Deloitte | De dónde sale | Pantalla |
|---|---|---|
| **La cola de alertas** | lista de alertas + resultados del triaje | Cola |
| **Qué consulta la IA** | `resultado["traza"]` | Detalle → «Qué ha consultado» |
| **En qué se basa para decidir** | `resultado["evidencia"]` + `ticket["evidence"]`, `ticket["enrichment"]` | Detalle → «En qué se basa» |
| **Qué propone** | `resultado["llm"]["analisis"]` (veredicto, resumen, acciones sugeridas) | Detalle → «Qué propone la IA» |
| **Dónde interviene la persona** | `ticket["recommended_actions"]` con `requires_approval` y `aprobador` + botón de aprobar | Detalle → «Decisión humana» |

Y además:
- **Las 10 alertas comunes del domingo se trían en directo.** Puede que no estén en el dataset: la UI tiene que aceptar **una alerta nueva pegando su JSON**.
- Criterios de evaluación: triaje correcto y argumentado · que funcione de verdad sobre los datos · **papeles claros para la IA y para la persona** · honestidad con lo que no resuelve.

**Idea visual que conviene usar en toda la UI:** distinguir siempre de quién es cada cosa, con un color o etiqueta fija:
- 🟣 **IA** (lo que propone el LLM): `llm.analisis`.
- 🔵 **Código / política** (reglas del SOC aplicadas sin IA): `politica`, `ticket.severity`, `ticket.escalation`, `aprobador`.
- 🟢 **Persona** (lo que decide el analista): aprobar o rechazar acciones, nombre de quien aprueba.

---

## 2. Puesta en marcha

Desde la raíz del repo (Windows, PowerShell), con `main` actualizado:

```powershell
git checkout main
git pull
git checkout -b feat/ui-streamlit
.venv\Scripts\activate
pip install -r requirements.txt
pip install streamlit
```

Añade `streamlit` a `requirements.txt` en tu rama.

**`.env`** (copia de `.env.example`; nunca se sube a git):
```
SOC_API_URL=http://127.0.0.1:8000      # 127.0.0.1, NO localhost (en Windows cada petición perdería 2 s)
LLM_API_KEY=uth-...                    # la clave ACTUAL del equipo (la de la pestaña Recursos de la plaza)
LLM_MODEL=ornith
LLM_THINKING=false
```

**Dos procesos a la vez:**
```powershell
# Terminal 1: API simulada del SOC (dejarla abierta)
uvicorn mock_soc_api:app --app-dir data/tarvia/06_herramientas --port 8000

# Terminal 2: la interfaz (con «python -m», desde la raíz del repo)
python -m streamlit run src/ui/app.py
```

Ubicación propuesta: `src/ui/app.py` (y, si crece, módulos en `src/ui/`). La UI importa del paquete `src`, así que **arráncala siempre con `python -m streamlit run` desde la raíz del repo**: así Python encuentra `src`. Con `streamlit run` a secas daría `ModuleNotFoundError: No module named 'src'`. No uses `sys.path.insert(...)` para arreglarlo: rompe `ruff` en el CI (import fuera de lugar).

---

## 3. Funciones del backend que usa la UI

Todas en `src/`. No hace falta saber cómo funcionan por dentro.

### Triaje — `src/triaje.py`

```python
from src.triaje import triar, triar_en_paralelo, triar_lote, cargar_alerta
from src.soc_client import SocClient, ErrorSOC
from src.llm import ErrorLLM

# Cargar una alerta: ID del dataset o ruta a un .json
cliente = SocClient()
alerta = cargar_alerta("ALR-20261009-011791", cliente)        # -> dict (lanza ErrorSOC si no existe)

# Triar UNA alerta (evidencia + LLM + política + ticket). ~10–25 s.
resultado = triar(alerta, cliente=cliente)                     # -> dict (ver sección 4)
resultado = triar(alerta, cliente=cliente, con_llm=False)      # solo evidencia (~1 s), sin LLM

# Triar VARIAS en paralelo: devuelve (posición, resultado) según TERMINAN (no en orden).
for posicion, resultado in triar_en_paralelo(["ALR-1", "ALR-2", alerta_dict], en_paralelo=5):
    ...  # pintar esta alerta en la cola en cuanto llega

# Igual, pero espera a todas y las devuelve en el orden original:
resultados = triar_lote(["ALR-1", "ALR-2"], en_paralelo=5)
```

- `triar_en_paralelo` acepta IDs del dataset, rutas a `.json` **o** diccionarios de alerta ya cargados (para las alertas nuevas pegadas en la UI).
- Paralelismo: por defecto 4, **máximo 8** (el servidor del DCC lo comparten todos los equipos). 10 alertas con 5 en paralelo ≈ 1 minuto.
- En lote, **si una alerta falla, el resto sigue**: esa alerta devuelve `{"alert_id": ..., "error": "...", "segundos_total": ...}`. Compruébalo con `"error" in resultado`.
- Con una sola alerta, los errores se lanzan como excepciones: `ErrorSOC` (API del SOC apagada o alerta inexistente) y `ErrorLLM` (clave no válida, servidor del DCC saturado…). Muéstralos con `st.error(str(e))`.

### Contención — `src/contencion.py`

```python
from src.contencion import ejecutar_accion, registrar_en_ticket, ErrorContencion

accion = resultado["ticket"]["recommended_actions"][i]
try:
    registros = ejecutar_accion(
        accion,
        aprobador="N2 - Ana López",            # NOMBRE de la persona que aprueba (lo escribe en la UI)
        motivo="Malware confirmado",           # opcional
        ticket_id=resultado["ticket"]["ticket_id"],
    )
    registrar_en_ticket(resultado["ticket"], registros)   # -> se ve en ticket["executed_actions"]
except ErrorContencion as e:
    st.error(str(e))   # p. ej. «Esta acción necesita la aprobación de N2: indica el nombre…» o «Prohibida por la política: Red OT…»
```

- Si `accion["requires_approval"]` es `True`, **sin `aprobador` no se ejecuta nada** (lanza `ErrorContencion`). El código nunca se aprueba a sí mismo: el nombre lo tiene que escribir una persona en la UI.
- Si `accion["permitida"]` es `False` (p. ej., red OT), **no se puede ejecutar nunca**: enseña el botón desactivado y la `nota`.
- `block_ioc` y `purge_email` no necesitan aprobación (los ejecuta el N1), pero igualmente solo se ejecutan cuando la persona pulsa el botón.
- Acciones `close` (cerrar ticket) y `human_review` **no** son contención: no las pases a `ejecutar_accion` (lanzaría error). Son botones de flujo de la UI.
- Registro de todo lo ejecutado: `SocClient().registro_contencion()` → lista de dicts (`action`, `target`, `approval_token`, `result`, `timestamp`…).
- Todo es **simulado**: la API solo escribe en `data/tarvia/06_herramientas/containment_log.jsonl` (borrarlo reinicia el registro antes de la demo).

### Lista de alertas para la cola

`SocClient` no tiene un método para listar; para la cola usa el fichero de la muestra (150 alertas variadas):

```python
import json
from pathlib import Path

@st.cache_data
def cargar_muestra() -> list[dict]:
    ruta = Path("data/tarvia/03_alertas/alertas_muestra_desarrollo.jsonl")
    return [json.loads(l) for l in ruta.open(encoding="utf-8")]
```

(Para todas las alertas: `alertas.jsonl` en la misma carpeta, 11.061; o la API `GET http://127.0.0.1:8000/alerts?status=new&limit=50&offset=0`.)

---

## 4. Estructura del resultado de `triar()` (datos reales)

Ejemplo real abreviado de `ALR-20261009-011791` (malware Latrodectus):

```text
resultado
├── alert_id: "ALR-20261009-011791"
├── segundos_evidencia: 1.2          ├── segundos_total: 24.9  (solo en triaje en lote)
├── traza: list                      ← 🔵 QUÉ HA CONSULTADO (cada llamada a la API del SOC)
│     {consulta: "/alerts/ALR-…", parametros: {...}, resultados: 1, ms: 13, cache: false}
│     (+ "desconocido": true si fue 404; + "estado" en las POST de contención)
├── evidencia: dict                  ← 🔵 EN QUÉ SE BASA
│     activos: {hostname: {type, criticality, zone, business_service, ...} | "DESCONOCIDO: …"}
│     usuarios: {upn: {department, title, privileged, vip, hr_events, ...} | "DESCONOCIDO: …"}
│     inteligencia: [{indicador, estado: malicious|suspicious|clean|unknown, tip: {...}, geo: {...}}]
│     sandbox: {sha256: {verdict, score, malware_family, ...} | "Sin informe…"}
│     cambios_aprobados: [{id: "CHG-…", titulo, inicio, fin, detalle, ...}]
│     eventos_citados_en_la_alerta: [{fuente, event_id, timestamp, ...}]
│     contexto_logs: [{fuente: "edr_events", busqueda: "usuario=marta.puig", total: 16, truncado: false, muestra: [...]}]
│     notas: [str]
├── llm                              ← 🟣 QUÉ PROPONE LA IA
│     modelo: "ornith"   tokens_entrada: 10024   tokens_salida: 2109   intentos: 1   segundos: 24.7
│     analisis:
│        title, verdict: "true_positive", confidence: 0.97, summary
│        evidence: [{source, event_id, finding}]          mitre: ["T1204.002", ...]
│        senales: {ejecucion_o_acceso_confirmado, identidad_vip_o_privilegiada, datos_personales_o_pagos,
│                  bloqueado_sin_actividad_posterior, actividad_autorizada, referencia_autorizacion}
│        acciones_sugeridas: [{action, target, justification}]
│        escalar_sugerido: true, motivo_escalado, open_questions: [str]
├── politica                         ← 🔵 LO QUE DECIDE EL CÓDIGO (no la IA)
│     veredicto: "true_positive"   veredicto_llm: "true_positive"   (si difieren: el código corrigió a la IA)
│     autorizacion: ""             (autorización verificada, si la hay)
│     criticidad: "Media"          origen_criticidad: "Criticidad Media del activo WS-BCN-1770 (Portátil)…"
│     severidad_regla: "high"      severidad_base: "high"   ajuste: 1   motivos_ajuste: ["+1: ejecución…"]
│     severidad_final: "critical"  razon_severidad: "Regla high × criticidad Media = high. Ajuste +1 (…). Final: critical."
│     decision: "escalar" | "cerrar" | "revisar"          motivos_escalado: [str]
│     sla: {tiempo_triaje: "15 min", escalado: "Inmediato a N2 de guardia por teléfono", notificar: "Responsable SOC y CISO"}
│     acciones: [...]  (las mismas que ticket.recommended_actions, sin close/human_review)
│     avisos: [str]    (correcciones del código a la IA y cosas que debe mirar una persona)
├── ticket                           ← EL TICKET OFICIAL (formato ticket_salida.schema.json de Deloitte)
│     ticket_id: "TKT-20261009-011791"   alert_ids: [...]   title   verdict   confidence   severity
│     severity_rationale   summary   mitre: [...]
│     affected: {users: [...], hosts: [...], business_services: [...], customers: [...]}
│     evidence: [{source, event_id, finding}]
│     enrichment: [{indicator, type: ip|domain|sha256, source: ti_feed|geoip_asn|sandbox, result}]
│     recommended_actions: [{action, target, requires_approval, justification, aprobador, permitida, nota}]
│     executed_actions: [...]            (se llena al aprobar/ejecutar contención)
│     escalation: {escalate: bool, to: str, reason: str}
│     open_questions: [str]              (preguntas de la IA + avisos de la política)
│     triage_seconds: 25
│     decision, sla, veredicto_llm, modelo   (extras para la UI)
└── ticket_errores: []               (vacío = el ticket cumple el esquema de Deloitte)
```

Valores posibles:
- `verdict`: `true_positive` · `benign_true_positive` · `false_positive` · `needs_more_info`
- `severity`: `informational` · `low` · `medium` · `high` · `critical`
- `decision`: `cerrar` · `escalar` · `revisar`
- `action`: `isolate_host` · `disable_user` · `revoke_sessions` · `reset_password` · `block_ioc` · `purge_email` · `disable_access_key` · (`close`, `human_review`: solo flujo de UI)
- `aprobador`: `—` (lo hace el N1) · `N1` · `N2` · `N2 + negocio` · `N2 + responsable de «…»` · `Responsable de Operaciones` (con `permitida: false`)

---

## 5. Pantallas recomendadas

### 5.1 Cola de alertas (pantalla principal)
- Tabla con: `alert_id`, regla (`rule_name`), severidad de la regla, **estado** (pendiente / triando / triada / error), y tras el triaje: **veredicto final**, **severidad final**, **decisión**, confianza, segundos.
- Colorear por severidad final (critical rojo, high naranja…) y marcar las `escalar` arriba.
- Filtros: regla, severidad, decisión, veredicto.
- Botón **«Triar seleccionadas»** (o «Triar las 10 del domingo») que usa `triar_en_paralelo` y va rellenando la tabla **a medida que terminan** (con `st.progress`).
- Contadores arriba: total, escaladas, cerradas, a revisar, tiempo total.

### 5.2 Detalle de una alerta (pestañas)
1. **Resumen**: título, veredicto 🟣 de la IA y veredicto final 🔵 (si son distintos, explicarlo con `politica.avisos`), **severidad final con `razon_severidad`**, decisión y SLA, confianza, afectados.
2. **Qué ha consultado** 🔵: la `traza` como tabla (consulta, resultados, ms), destacando las `desconocido` (404 = «no está en la CMDB/directorio»). Total de consultas y segundos.
3. **En qué se basa** 🔵: activos y usuarios (criticidad, departamento, VIP/privilegiado), inteligencia con su estado (`unknown` ≠ `clean`, decirlo), sandbox, **cambios aprobados**, eventos citados y `contexto_logs` (fuente, búsqueda, total; la `muestra` dentro de un `st.expander`).
4. **Qué propone la IA** 🟣: `summary`, `evidence` (tabla source/event_id/finding), MITRE, `senales`, `open_questions`, acciones sugeridas.
5. **Decisión humana** 🟢: cada acción de `ticket.recommended_actions` con su `aprobador`; si `requires_approval`, un campo «Nombre de quien aprueba» y botón **Aprobar y ejecutar**; si no, botón **Ejecutar**; si `permitida` es `false`, botón desactivado + `nota`. Botón **Rechazar** (solo lo registra en la UI). Debajo, `executed_actions` y el registro de contención.
6. **Ticket** : `st.json(resultado["ticket"])` + `st.download_button` para descargarlo, y un indicador «✅ cumple el esquema de Deloitte» si `ticket_errores` está vacío.

### 5.3 Alerta nueva (para el domingo)
- `st.text_area` para **pegar el JSON** de una alerta → `json.loads` → `triar(alerta)` → mismo detalle que 5.2.
- Opción de subir un `.json` con `st.file_uploader`.
- Validar que tenga al menos `alert_id`, `rule_id`, `severity`, `created_at`, `entities`; si no, mensaje claro.

### 5.4 «Quién decide qué» y «Límites» (pequeña página o barra lateral)
- Esquema fijo: 🟣 IA propone → 🔵 código aplica la política (matriz, autorizaciones, escalado, permisos) → 🟢 persona aprueba la contención.
- Límites honestos (de `evaluacion/revision-gold-set.md` y el plan): acierto medido en el gold set, inestabilidad en casos límite, sin nivel 2 (agrupación), etiquetas sin revisión humana independiente, dependencia del servidor del DCC.

---

## 6. Código de partida (orientativo)

Esqueleto para empezar; ajústalo a gusto. Usa solo funciones estándar de Streamlit.

```python
# src/ui/app.py
import json
from pathlib import Path

import streamlit as st

from src.contencion import ErrorContencion, ejecutar_accion, registrar_en_ticket
from src.llm import ErrorLLM
from src.soc_client import ErrorSOC
from src.triaje import triar, triar_en_paralelo

st.set_page_config(page_title="TEMIPO · Triaje N1", layout="wide")
st.session_state.setdefault("resultados", {})   # alert_id -> resultado


@st.cache_data
def cargar_muestra() -> list[dict]:
    ruta = Path("data/tarvia/03_alertas/alertas_muestra_desarrollo.jsonl")
    return [json.loads(l) for l in ruta.open(encoding="utf-8")]


alertas = {a["alert_id"]: a for a in cargar_muestra()}

st.title("Triaje N1 del SOC de Tarvia")
seleccion = st.multiselect("Alertas a triar", list(alertas), max_selections=10)

if st.button("Triar en paralelo", disabled=not seleccion):
    barra = st.progress(0.0, text="Triando…")
    # El generador se recorre AQUÍ (hilo principal): los hilos internos no pueden pintar en pantalla.
    for hechas, (_, r) in enumerate(triar_en_paralelo([alertas[i] for i in seleccion], en_paralelo=5), 1):
        st.session_state.resultados[r["alert_id"]] = r
        barra.progress(hechas / len(seleccion), text=f"{hechas}/{len(seleccion)}: {r['alert_id']}")

# Cola: tabla con lo ya triado
filas = []
for aid, r in st.session_state.resultados.items():
    if "error" in r:
        filas.append({"alerta": aid, "estado": "error", "detalle": r["error"]})
        continue
    t = r["ticket"]
    filas.append({"alerta": aid, "veredicto": t["verdict"], "severidad": t["severity"],
                  "decisión": t["decision"], "confianza": t["confidence"], "segundos": t["triage_seconds"]})
st.dataframe(filas, use_container_width=True)

# Detalle de una alerta triada
elegida = st.selectbox("Ver detalle", [f["alerta"] for f in filas if "veredicto" in f])
if elegida:
    r = st.session_state.resultados[elegida]
    t, p, ia = r["ticket"], r["politica"], r["llm"]["analisis"]
    resumen, consultas, base, propuesta, humana, ticket = st.tabs(
        ["Resumen", "Qué ha consultado", "En qué se basa", "Qué propone la IA", "Decisión humana", "Ticket"])

    with resumen:
        st.subheader(t["title"])
        c1, c2, c3 = st.columns(3)
        c1.metric("🟣 Veredicto IA", ia["verdict"], f"confianza {ia['confidence']}")
        c2.metric("🔵 Veredicto final", t["verdict"])
        c3.metric("🔵 Severidad", t["severity"], t["decision"])
        st.info(p["razon_severidad"])
        for aviso in p["avisos"]:
            st.warning(aviso)

    with consultas:
        st.dataframe(r["traza"], use_container_width=True)

    with base:
        st.json(r["evidencia"], expanded=False)   # mejor: secciones bonitas (activos, intel, cambios…)

    with propuesta:
        st.write(ia["summary"])
        st.dataframe(ia["evidence"], use_container_width=True)

    with humana:
        for i, accion in enumerate(t["recommended_actions"]):
            if accion["action"] in ("close", "human_review"):
                st.write(f"**{accion['action']}** — {accion['justification']}")
                continue
            st.markdown(f"**{accion['action']}** → `{accion['target']}` · aprueba: **{accion['aprobador']}**")
            if not accion["permitida"]:
                st.button("Prohibida", key=f"x{i}", disabled=True, help=accion["nota"])
                continue
            nombre = st.text_input("Nombre de quien aprueba", key=f"n{i}") if accion["requires_approval"] else ""
            if st.button("Aprobar y ejecutar" if accion["requires_approval"] else "Ejecutar", key=f"b{i}"):
                try:
                    registros = ejecutar_accion(accion, aprobador=nombre, ticket_id=t["ticket_id"])
                    registrar_en_ticket(t, registros)
                    st.success(f"Ejecutada: {registros}")
                except ErrorContencion as e:
                    st.error(str(e))
        st.write("Acciones ejecutadas:", t["executed_actions"])

    with ticket:
        st.success("Cumple el esquema de Deloitte") if not r["ticket_errores"] else st.error(r["ticket_errores"])
        st.json(t)
        st.download_button("Descargar ticket", json.dumps(t, ensure_ascii=False, indent=2), f"{t['ticket_id']}.json")

# Alerta nueva (domingo): pegar JSON
with st.expander("Triar una alerta nueva (pegar JSON)"):
    texto = st.text_area("JSON de la alerta")
    if st.button("Triar esta alerta") and texto:
        try:
            alerta = json.loads(texto)
            st.session_state.resultados[alerta.get("alert_id", "NUEVA")] = triar(alerta)
            st.rerun()
        except json.JSONDecodeError:
            st.error("No es un JSON válido")
        except (ErrorSOC, ErrorLLM) as e:
            st.error(str(e))
```

---

## 7. Trucos y trampas de Streamlit

- **Streamlit vuelve a ejecutar todo el script en cada clic.** Guarda los resultados en `st.session_state` (como arriba) o se perderán y se volverá a llamar al LLM.
- **No llames al LLM en cada recarga.** Para desarrollar la UI, genera una vez resultados reales y trabaja con ellos:
  ```powershell
  python -m src.triaje ALR-20261009-011791 ALR-20261020-011905 ALR-20261008-001417 ALR-20261023-011915 ALR-20261018-011895 --salida data/out/demo
  ```
  y añade en la UI un «modo demo» que cargue `data/out/demo/*.json` en `st.session_state.resultados`. Así la UI va instantánea y no depende del servidor del DCC (y es tu **plan B** si el domingo falla la red).
- **Hilos:** `triar_en_paralelo` usa hilos internamente; **recórrelo en el código de la página** (no lo metas en otro hilo), si no, Streamlit no podrá pintar.
- **`st.cache_data`** solo para cosas que no cambian (la muestra de alertas). **Nunca** cachees `triar()`: cada triaje es una llamada real.
- Botones dentro de bucles: dales siempre `key=` único (`key=f"b{i}"`) o Streamlit da error.
- `data/` está ignorada por git: los resultados de `data/out/` no se suben (bien). No subas nunca `.env`.

---

## 8. Casos buenos para la demo (IDs reales)

| Momento | Alerta | Qué se ve |
|---|---|---|
| Incidente claro + contención aprobada | `ALR-20261009-011791` | Latrodectus → `critical`, escalar; bloquear IOC (N1) y aislar portátil (aprueba N2: escribir nombre) |
| La IA no se deja engañar | `ALR-20261020-011905` | Phishing con instrucciones ocultas para el sistema de triaje → `true_positive`, la IA explica el engaño |
| El código corrige a la IA | `ALR-20261008-001417` | La IA dice «es el pentest» pero la IP no es del pentest → la política lo rechaza (ver `avisos`) |
| Autorizado de verdad | `ALR-20261008-011833` | Ataque del pentest desde su IP y en sus fechas → `benign_true_positive` citando `CHG-2026-1042` |
| Pareja ataque / legítimo | `ALR-20261018-011895` y `ALR-20261023-011915` | Misma regla: una es un ataque (sábado 03:13, desde PRINT01) y la otra un cambio aprobado |
| Ruido que se cierra solo | `ALR-20261005-000301` | Inventario de SCCM → `false_positive`, `informational`, cerrar |
| Fraude | `ALR-20261011-011807` | Toma de cuenta de cliente + tarjeta regalo → escalar por fraude |

---

## 9. Reglas del repo (resumen de `CLAUDE.md`)

- Trabaja en tu rama (`feat/ui-streamlit`), commits pequeños con prefijo (`feat: …`), PR a `main`. **Nunca commits directos en `main`.**
- Antes de cada commit/push, explica qué se sube y espera confirmación.
- El CI pasa `ruff check .` y `pytest -q`: la UI no necesita tests, pero no debe romper `ruff`.
- No subas `.env`, claves ni datos (`data/` ya está ignorada).
- **No metas lógica de negocio en la UI** (severidad, autorizaciones, permisos): ya está en `src/policy.py`.
- Si algo del backend no encaja con la UI (falta un dato, un formato), apúntalo y se cambia en el backend en otra rama.

## 10. Checklist antes de la demo

- [ ] Cola con al menos 10 alertas triadas en paralelo y coloreadas por severidad.
- [ ] Detalle con las 5 pestañas: resumen, consultas, evidencia, propuesta de la IA, decisión humana.
- [ ] Botón de aprobar que pide el nombre y rechaza sin él; acción OT desactivada.
- [ ] Pegar una alerta nueva en JSON y triarla en directo.
- [ ] Modo demo con resultados guardados (plan B sin red).
- [ ] Indicadores 🟣 IA / 🔵 código / 🟢 persona visibles en todas las pantallas.
- [ ] `containment_log.jsonl` borrado antes de empezar la demo.
- [ ] Vídeo de respaldo grabado.
