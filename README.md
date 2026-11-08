# TEMIPO — UAB The Hack · Reto Deloitte (Ciber + IA)

> Un sistema que hace el **triaje de nivel 1 de las alertas de un SOC**: investiga cada alerta con los datos de la empresa, propone un veredicto argumentado y deja a la persona del SOC una conclusión lista para decidir. **La IA propone, el código decide la severidad y los permisos, y una persona aprueba.**

## 👥 Equipo

Estudiantes del grado de Inteligencia Artificial de la UAB. No hay áreas fijas: todos hemos hecho de todo.

| Nombre | GitHub |
|--------|--------|
| Miriam Morales | [@miiimiii18](https://github.com/miiimiii18) |
| Pol Orellana | [@polore4](https://github.com/polore4) |
| Teia Torrent | — |

## 🎯 El reto

Deloitte nos pide un sistema con IA para el **SOC de Tarvia Group**, un retailer ficticio de moda y hogar con sede en Barcelona. El SIEM genera miles de alertas (11.061 en cuatro semanas de datos sintéticos) y casi todas son ruido; entre ellas hay ataques reales. El sistema tiene que recibir cada alerta, investigarla con los datos disponibles (inventario, logs, inteligencia, calendario de cambios) y entregar al analista un veredicto, una severidad y una recomendación.

El reto tiene cuatro niveles: **1 · triaje básico**, **2 · triaje con criterio** (agrupar alertas del mismo ataque, matriz de severidad, descartar lo autorizado), **3 · investigación** (cadena de ataque, alcance, relación con otros incidentes) y **4 · respuesta** (contención en una API simulada, siempre con aprobación humana).

Fuente oficial: [`dttdfr/DTT-UAB-The-Hack`](https://github.com/dttdfr/DTT-UAB-The-Hack).

## 💡 Nuestra solución

**Hemos llegado a los cuatro niveles**, con el nivel 1 como base sólida y medida.

| Nivel | Qué hace | Dónde |
|---|---|---|
| 1 · Triaje | Reúne la evidencia según el runbook (±24 h), la IA propone veredicto y argumentos, el código aplica la política y sale un ticket con el esquema de Deloitte | `src/evidencia.py`, `src/llm.py`, `src/policy.py`, `src/ticket.py`, `src/triaje.py` |
| 2 · Criterio | Matriz regla × criticidad del activo (±1), autorizaciones **verificadas con datos** (cambio, fechas e IP de origen), deduplicación y agrupación del mismo ataque en un ticket único | `src/policy.py`, `src/agrupar.py` |
| 3 · Investigación | Informe de incidente (`informe_incidente.schema.json`): el código construye cronología, alcance, contención y notificaciones; la IA redacta causa raíz y acceso inicial | `src/investigacion.py` |
| 4 · Respuesta | Contención en la API simulada solo con la aprobación de una persona con nombre; nunca sobre la red OT | `src/contencion.py` |

### Quién decide qué

| 🟣 Decide la IA | 🔵 Decide el código | 🟢 Decide la persona |
|---|---|---|
| Veredicto, confianza y argumentación (citando eventos) | Severidad final, escalado obligatorio, verificación de autorizaciones, quién aprueba cada acción | Aprobar o rechazar la contención, cerrar o pasar a N2, corregir el veredicto (con nombre y motivo) |

```
alerta (JSON) ─► evidencia (API del SOC, ±24 h, cada consulta trazada)
              ─► IA ornith (veredicto, confianza, argumentos; JSON validado)
              ─► política en CÓDIGO (severidad, escalado, autorizaciones, permisos)
              ─► ticket (esquema de Deloitte) ─► web ─► persona aprueba ─► contención en la API simulada
varias alertas triadas ─► agrupación ─► ticket único del grupo ─► informe de investigación (N3)
```

- **Qué aporta la IA:** lee alertas y logs heterogéneos como lo haría un analista, relaciona evidencias que no están en la propia alerta y redacta un veredicto argumentado que se puede revisar.
- **Qué aporta la parte de ciberseguridad:** la política del SOC (matriz de severidad, escalado, permisos de contención) está en código con tests, no en el prompt. Una autorización citada de palabra no basta: se comprueba en el calendario de cambios. Todo lo que viene de alertas y logs se trata como **dato no fiable** (el atacante escribe parte de los datos: defensa contra *prompt injection*), y un indicador desconocido **no** cuenta como limpio.
- **Modelo:** `ornith` (Ornith 1.5), el LLM que ofrece la organización en las GPU del DCC (UAB). Gratuito y sin enviar datos a proveedores externos.

### Resultados medidos

Sobre 42 alertas del dataset etiquetadas por nosotros (**sin revisión externa**), cada una triada 2 veces y en tres ejecuciones distintas (7-nov-2026):

| Métrica | Acierto |
|---|---|
| Veredicto | **80–86 %** |
| Severidad final | 85–89 % |
| Decisión (cerrar / revisar / escalar) | 87–90 % |

- Damos un **rango** porque el modelo no siempre responde igual: entre dos ejecuciones cambian de 2 a 6 casos.
- 150 de 150 alertas de la muestra de desarrollo triadas sin errores y con tickets válidos.
- 16 de 16 triajes correctos en alertas con instrucciones ocultas para el sistema (*prompt injection*).
- ~13–15 s por alerta; 10 alertas en ~1 min con 5 en paralelo. Coste 0.

Detalle en [`writeups/04-evaluacion.md`](writeups/04-evaluacion.md) y [`evaluacion/`](evaluacion/).

### Lo que no resuelve

Lo contamos con detalle en **[`docs/limitaciones.md`](docs/limitaciones.md)**. Lo más importante:
- La IA se equivoca y es inestable: puede escalar un falso positivo o dejar un ataque en «necesita más información». Antes de añadir reglas en código llegó a cerrar un ataque; desde entonces no ha vuelto a pasar en las pruebas, pero son reglas concretas, no una garantía. Por eso la persona revisa también los cierres.
- Las etiquetas del conjunto de evaluación son nuestras: el acierto es una estimación sobre un conjunto pequeño.
- La agrupación y la investigación solo trabajan con las alertas ya triadas; no buscan por su cuenta en todo el dataset.
- No consultamos servicios de reputación externos y el contexto de los logs se limita a ±24 h.
- Depende del servidor compartido del DCC (para eso está el **modo demo**).

## 🚀 Cómo ejecutarlo

Guía completa, paso a paso y con los problemas típicos: **[`docs/arrancar.md`](docs/arrancar.md)**.

Resumen (Windows, PowerShell):
```powershell
git clone https://github.com/miiimiii18/hackathon-uab-deloitte.git
cd hackathon-uab-deloitte
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
git clone https://github.com/dttdfr/DTT-UAB-The-Hack.git data/tarvia   # dataset de Deloitte
copy .env.example .env                                                   # pon LLM_API_KEY (NUNCA subas .env)

# Terminal 1: API simulada del SOC
.venv\Scripts\python -m uvicorn mock_soc_api:app --app-dir data/tarvia/06_herramientas --host 127.0.0.1 --port 8000
# Terminal 2: la web → http://127.0.0.1:8080
.venv\Scripts\python -m src.web
# Terminal 3 (una vez por ordenador): resultados guardados para el modo demo
.venv\Scripts\python -m scripts.preparar_demo --informe
```

Usad siempre `127.0.0.1` y no `localhost` (en Windows, `localhost` añade ~2 s a cada consulta).

Desde la terminal, sin la web:
```powershell
.venv\Scripts\python -m src.triaje ALR-20261005-000301                # una alerta del dataset
.venv\Scripts\python -m src.triaje mi_alerta.json                     # una alerta nueva
.venv\Scripts\python -m src.triaje ALR-1 ALR-2 --salida data/out/lote # varias, en paralelo
.venv\Scripts\python -m scripts.evaluar --repeticiones 2              # evaluación con el gold set
.venv\Scripts\python -m pytest -q                                     # 177 tests
```

## 🖥️ La web de la demo

Web propia (FastAPI + HTML/CSS/JS sin build ni recursos de terceros). Cómo está hecha: [`docs/web.md`](docs/web.md).

- **Cola de alertas** que se trían en paralelo, con su avance por Evidencia → IA → Política → Persona, filtros y la etiqueta «Mismo ataque».
- **Detalle** de cada alerta: qué ha consultado el sistema, en qué se basa, qué propone la IA, qué decide el código y qué falta por decidir a la persona.
- **Cargar alertas**: pegar un JSON nuevo, subir un fichero o elegir del dataset (para las 10 alertas en directo).
- **Informe de investigación** (N3) de lo escalado y **registro de contención** con quién aprobó cada acción.
- **Modo demo**: reproduce los resultados guardados si falla la red o el servidor del modelo.

## 🗂️ Estructura

```
├── src/            # backend: evidencia, LLM, política, ticket, triaje, agrupación, investigación, contención
│   ├── esquemas/   # esquemas de salida de Deloitte (ticket e informe)
│   └── web/        # API FastAPI y front estático
├── scripts/        # evaluar.py (gold set) y preparar_demo.py (modo demo)
├── evaluacion/     # casos etiquetados, alertas inventadas y resultados
├── tests/          # tests con pytest (los ejecuta el CI con ruff)
├── docs/           # plan de trabajo, arranque, web, limitaciones y pitch
├── writeups/       # un documento por nivel resuelto
└── data/           # dataset y resultados locales (ignorados por git)
```

## 📽️ Demo y presentación

- Guion de 5 minutos y plan B: [`docs/pitch.md`](docs/pitch.md).
- Cómo lo hemos construido, nivel a nivel: [`writeups/`](writeups/).
- Hoja de ruta y decisiones: [`docs/plan-de-trabajo.md`](docs/plan-de-trabajo.md).

## ⚖️ Ética y alcance

- Todas las pruebas se hacen **solo** sobre los sistemas y datos que la organización del reto ha autorizado: el dataset sintético de Tarvia y su API simulada.
- La contención solo se ejecuta contra la API simulada, con aprobación humana registrada. **Nunca** se actúa sobre la red OT.
- Algunos indicadores maliciosos del dataset son reales: **no se visitan, descargan ni escanean**.
- El LLM es el de la organización: los datos no salen a proveedores de pago. La web solo escucha en `127.0.0.1` y no carga recursos externos.
- No se suben credenciales, claves ni datos sensibles al repositorio (`.env` está ignorado; `.env.example` no lleva valores).
