# Nivel 1: triaje básico

- **Categoría:** IA + ciberseguridad (SOC)
- **Responsable:** todo el equipo TEMIPO
- **Estado:** 🟢 resuelto
- **Resultado:** 150/150 alertas de la muestra triadas sin errores; 86 % de veredictos acertados en el gold set (72/84 triajes, 42 casos × 2 repeticiones; severidad 89 %, decisión 90 %).

## Enunciado
Para cada alerta del SIEM: entender qué ha pasado, enriquecer con contexto e inteligencia, dar veredicto, severidad y recomendación (cerrar o escalar). Salida en el formato `ticket_salida.schema.json` de Deloitte.

## Cómo lo resolvimos
1. **Evidencia determinista** (`src/evidencia.py`): según el runbook de la alerta (RB-01…RB-10) consulta la API simulada del SOC: activo (CMDB), usuario, inteligencia (TIP, GeoIP, sandbox), cambios aprobados y logs filtrados por entidad en ±24 h. No se leen logs enteros ni solo los `related_events`: la clave suele estar fuera.
2. **Cliente propio** (`src/soc_client.py`): caché, traza de cada consulta, coincidencia exacta (la API busca por subcadena) y un 404 de activo o usuario cuenta como dato («desconocido»), no como error.
3. **Análisis del LLM** (`src/llm.py`): modelo `ornith` de la organización. Recibe la evidencia marcada como datos no fiables y devuelve JSON validado: veredicto, confianza, evidencias citadas, señales (ejecución confirmada, VIP, datos personales…) y preguntas abiertas.
4. **Política en código** (`src/policy.py`): verifica el veredicto, calcula la severidad con la matriz y decide escalado y SLA. El LLM no decide ninguno de los tres.
5. **Ticket** (`src/ticket.py`): se valida contra el esquema de Deloitte en cada ejecución (`ticket_errores` vacío = válido).
6. **Tres estados de enriquecimiento:** `malicious`, `clean`, `unknown`. Un dato desconocido nunca cuenta como limpio.

## Herramientas
Python 3.11, FastAPI, pydantic, jsonschema, pytest, ruff; LLM `ornith` del DCC (UAB) con API compatible con OpenAI.

## Lo que aprendimos
- Con el modelo sin razonar (`LLM_THINKING=false`) tarda ~13 s por alerta y acierta lo mismo que razonando (~100 s). Con 5 alertas en paralelo, 10 alertas en ~1 min.
- Usar `127.0.0.1` y no `localhost` en Windows: pasamos de 20–40 s a ~1 s de evidencia.
- Los modelos locales con Ollama (`gpt-oss:20b`, `qwen3:8b`) eran 5–10 veces más lentos y acertaban menos.
- Un 15 % de fallos: el modelo flojea con accesos fuera de horario de proveedores y con falsos «túneles DNS». Ver `docs/limitaciones.md`.
