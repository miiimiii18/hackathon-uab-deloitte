# Evaluación honesta

- **Categoría:** IA + ciberseguridad (SOC)
- **Responsable:** todo el equipo TEMIPO
- **Estado:** 🟢 resuelto (veredicto, severidad y decisión medidos)

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
| **7-nov, ejecución A, 42 casos × 2** | **veredicto 72/84 (86 %), severidad 66/74 (89 %), decisión 63/70 (90 %)** |
| 7-nov, ejecución B (tras endurecer, mismo conjunto) | veredicto 68/84 (81 %), severidad 63/74 (85 %), decisión 63/70 (90 %) |
| 7-nov, ejecución C (tras deduplicación, relación de incidentes y alertas pobres, que no cambian ninguna alerta del gold set) | veredicto 67/84 (80 %), severidad 63/74 (85 %), decisión 61/70 (87 %); ningún ataque cerrado |
| Alertas inventadas, 9 × 2 (A → B → C) | veredicto 15/18 → 16/18 → 15/18, severidad 8/10 → 10/10 → 10/10, decisión 12/14 → 14/14 → 14/14 |

Por categoría: prompt injection, autorizaciones, Vela y matices 100 %; incidentes 77 %; ruido 78 %.

## Severidad y decisión
Se añadieron a cada caso `severidades_validas` y `decisiones_validas` (cerrar / revisar / escalar), **escritas antes de ejecutar** y con el criterio de la política: falso positivo → `informational` y cerrar; autorizado → `informational` o `low`; ataque con ejecución, VIP, datos personales o pagos → sube un nivel y se escala. Los casos ambiguos no se etiquetan y no cuentan (37 de 42 y 7 de 9). `scripts/evaluar.py` puntúa las tres métricas y lista cada fallo con lo esperado y lo obtenido (`evaluacion/resultados-2026-11-07.txt`).

## Fallos tipo
1. **Ataques que se cerraban** (el más grave; endurecido, ver arriba): los accesos de madrugada de `ext.logisoft` (`ALR-20261018-011879`) y el volcado de LSASS con instrucciones ocultas (`INV-09`) salieron `false_positive` y se cerraron en 1 de 2 repeticiones.
2. **Falsos positivos que se escalan**: fotos de campaña a WeTransfer, bucket por Terraform, antivirus e5.sk y un cliente que se corrige en Vela. Salen como ataque de severidad alta o crítica.
3. **Ataques que se quedan en `needs_more_info`**: túnel DNS desde WMS01 y el otro acceso de Logisoft.
4. **Autorización verificable en revisión**: el escaneo de NESSUS01 (`INV-05`) pasa a `needs_more_info` en 1 de 2.

## Variación entre ejecuciones
A y B son el mismo conjunto de casos, con el modelo sin tocar; la diferencia (4 casos de 84) viene del propio modelo, sobre todo en el ruido (23/30 frente a 19/30: el cliente que se corrige en Vela y el bucket por Terraform salieron como ataque). El endurecimiento solo se activó en 2 triajes, ambos de ataques. La ejecución C (mismo conjunto; los cambios de ese día no tocan ninguna alerta del gold set) dio 67/84: otra vez variación del modelo, y de nuevo sin cerrar ningún ataque (los 3 incidentes fallados quedan en `needs_more_info`). **Hay que leer las cifras como un rango (80–86 %), no como un número exacto.**

## Endurecimiento (fallo 1)
Dos reglas fijas en `src/policy.py`: (1) la cuenta `ext.logisoft` fuera de lunes a viernes de 8 a 18 h (hora de España) no se cierra como falsa alarma ni como autorizada sin un cambio verificado, y (2) una regla de severidad crítica no se cierra sin una autorización verificada. En ambos casos el veredicto pasa a `needs_more_info`. Resultado: 18 de 18 repeticiones dirigidas sin cierres (ALR-…011879, ALR-…011877 e INV-09), y ningún ataque cerrado en la ejecución B. Límite: son reglas concretas, no una garantía general.

## Coherencia de la confianza
Sobre 102 triajes: sin logs la confianza cae (media 0,25), pero con un indicador `unknown` apenas baja (0,86 frente a 0,87). `unknown` aparece en 66 de los 102, así que bajarla por código sería ruido; no se tocó. Sí discrimina el acierto: media 0,88 en aciertos y 0,67 en fallos, con 2 de 15 fallos en 0,9 o más.

## Pendiente
- Revisar las etiquetas con una persona ajena al equipo. (El endurecimiento en código de los dos ataques cerrados se hizo el 7-nov en `src/policy.py`.)

## Lo que aprendimos
- Las cifras varían ±2 casos entre ejecuciones: hay que repetir.
- Un script que tarda 5 minutos y se cae al imprimir sin haber guardado es un error caro: ahora guarda primero (en Windows, con la salida a fichero, la consola no codifica los emojis).
- Los fallos que se repiten son del modelo (accesos de proveedores de madrugada, falso túnel DNS de antivirus).
- Probar con alertas inventadas destapó que una autorización que no encaja se cerraba como falso positivo.
