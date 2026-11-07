# Evaluación honesta

- **Categoría:** IA + ciberseguridad (SOC)
- **Responsable:** todo el equipo TEMIPO
- **Estado:** 🟡 en curso (veredicto medido; severidad y escalado pendientes)

## Enunciado
Las alertas no traen la respuesta correcta; hay que construir nuestra propia verdad y medir sin autoengaño.

## Cómo lo hicimos
1. **Gold set de 42 alertas** (`evaluacion/casos.json`): todas las de reglas raras de la muestra más ruido representativo, etiquetadas desde la evidencia de la API. Cada caso lleva los veredictos válidos y el porqué. Revisión por Claude con segunda pasada; **sin revisión humana independiente** (ver `evaluacion/revision-gold-set.md`).
2. **Script** `python -m scripts.evaluar --repeticiones N` mide el acierto por categoría y la estabilidad.
3. **Prompt injection:** 12 alertas del dataset llevan instrucciones ocultas; probamos 6 (4 de correo + 2 de Vela): 16/16 correctas con repeticiones.
4. **Robustez:** 9 alertas inventadas (`evaluacion/alertas_inventadas/`) de 8 familias, una casi vacía y otra sin datos en los logs.

## Resultados
| Medida | Resultado |
|---|---|
| Gold set, línea base | 34/41 (83 %) |
| Tras arreglar 2 fallos de código | 35/41 (85 %) |
| 42 casos × 3 repeticiones | 107/126 (85 %); 34 de 42 casos estables |
| Con reglas duras y `needs_more_info` | gold set 74/84 (88 %), inventadas 16/18 (89 %) |
| Tiempo | ~13 s por alerta; mediana 16 s en la muestra de 150 (7,4 min con 6 en paralelo) |
| Coste | 0 (LLM de la organización) |

Por categoría: prompt injection, autorizaciones, Vela y matices 100 %; incidentes 77 %; ruido 78 %.

## Pendiente
- Medir también acierto de severidad y de escalado, y anotar los fallos tipo.

## Lo que aprendimos
- Las cifras varían ±2 casos entre ejecuciones: hay que repetir.
- Los fallos que se repiten son del modelo (accesos de proveedores de madrugada, falso túnel DNS de antivirus).
- Probar con alertas inventadas destapó que una autorización que no encaja se cerraba como falso positivo.
