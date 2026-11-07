# Lo que esta solución no resuelve

Documento para la defensa y base del panel «Lo que no resuelve» de la web. Las cifras salen de `evaluacion/` y de `docs/plan-de-trabajo.md` (medidas el 7-nov-2026).

## 1. No sabemos con certeza cuánto acertamos

- Las alertas del dataset **no traen la respuesta correcta**. Medimos contra 42 alertas etiquetadas por nosotros (`evaluacion/casos.json`), más 9 inventadas.
- Esas etiquetas las ha revisado Claude con una segunda pasada de evidencia; **no hay revisión humana independiente**.
- Mediciones del 7-nov (42 casos repetidos 2 veces, dos ejecuciones seguidas): **veredicto 81–86 % (68 y 72 de 84), severidad 85–89 %, decisión (cerrar, revisar o escalar) 90 %**. Entre una ejecución y otra cambió el veredicto de 4 casos sin tocar nada relevante: esa es la precisión real de la medida. Es una estimación sobre un conjunto pequeño, no una garantía.
- La severidad y la decisión se miden solo en los 37 casos que tienen etiqueta (el resto es ambiguo y no cuenta). Esas etiquetas las escribimos antes de ejecutar la evaluación, pero siguen siendo nuestras.

## 2. La IA se equivoca y no siempre da la misma respuesta

- Entre 2 y 6 de los 42 casos (según la ejecución) dieron veredictos distintos entre repeticiones.
- Fallos que se repiten:
  - Accesos de un proveedor externo de madrugada y fuera de horario: la IA los deja en «necesita más información» en vez de marcarlos como ataque.
  - Un «túnel DNS» que en realidad es un antivirus consultando reputación: la IA lo da por ataque.
- **El fallo más grave: a veces se cerraba un ataque.** Los accesos de madrugada del proveedor externo y un volcado de credenciales con instrucciones ocultas salieron como falsa alarma en una de las dos repeticiones. Se endureció con dos reglas en código (la cuenta del proveedor fuera de su horario y las detecciones de severidad crítica no se cierran sin una autorización verificada) y desde entonces no se cerró ningún ataque en las pruebas (dos ejecuciones completas y 18 repeticiones dirigidas). Pero son reglas concretas: un ataque de otro tipo y de severidad no crítica aún podría cerrarse, por eso la persona debe revisar también los cierres.
- También ocurre al revés: algunas actividades legítimas (fotos de campaña enviadas a un servicio de transferencia, un bucket publicado por Terraform, un antivirus) se escalan como ataques críticos sin necesidad.
- Una autorización verificable (el escaneo semanal de seguridad) a veces pasa a revisión humana en vez de cerrarse.
- La confianza que da la IA ayuda, pero no es una garantía: media 0,88 cuando acierta y 0,67 cuando falla, aunque 2 de 15 fallos llevaban 0,9 o más. Con un indicador desconocido casi no baja.
- Por eso la severidad, el escalado y los permisos **no los decide la IA**: están en código con tests, y una persona aprueba toda acción que no sea de bajo riesgo.
- Un triaje falló por tiempo (más de 300 s) porque el servidor de modelos es compartido con los demás equipos.

## 3. Depende de la calidad de los datos

- Un indicador que la inteligencia interna no conoce se trata como **desconocido, no como limpio**: baja la confianza, pero no demuestra nada.
- Si un equipo o un usuario no aparece en el inventario, el sistema sigue y lo anota, pero la severidad se calcula con valores por defecto.
- No consultamos servicios de reputación externos (VirusTotal, AbuseIPDB…). Solo usamos la inteligencia interna del dataset.
- La búsqueda de contexto en los registros se limita a ±24 h alrededor de la alerta. Una causa anterior a esa ventana no se ve.

## 4. Lo que el sistema todavía no hace

- **Alertas pegadas incompletas:** la web exige `alert_id`, `rule_id`, `severity`, `created_at` y `entities` antes de triar. Todas las alertas del dataset los traen, pero una alerta más pobre se rechaza en la interfaz con el motivo; el motor sí la trataría (sale `needs_more_info`) con `python -m src.triaje alerta.json`.
- **Agrupación parcial** (nivel 2): une en un solo ticket las alertas ya triadas de la cola que comparten usuario, equipo, IP, dominio, hash, cliente, identidad cloud o correo, y las escala. No busca por su cuenta otras alertas relacionadas en el dataset, y no une dos grupos si ninguna alerta nombra la entidad que los conecta (los accesos de un proveedor externo y el túnel DNS posterior desde el servidor al que entraba salen como dos casos). Solo agrupa lo que sigue siendo sospechoso tras el triaje, así que depende de que el veredicto individual sea correcto.
- **Reconstruir la cadena de ataque** (nivel 3): no genera el informe de incidente.
- La deduplicación (unas 920 alertas exactas repetidas) está hecha y probada, pero la cola todavía no la aplica sola.
- No hay playbook propio por cada una de las 44 reglas: hay uno por runbook (RB-01 a RB-10) y las reglas poco frecuentes siguen un camino más genérico.

## 5. Escala y coste real

- Medido: ~13 s por alerta con el modelo `ornith` de la organización; 10 alertas en ~1 min con 5 a la vez; coste cero porque el modelo es gratuito.
- No se ha probado con los ~4.000 alertas diarias de un SOC real, ni con un modelo distinto. El servidor del DCC es compartido y puede saturarse.
- No hemos triado las 11.061 alertas del mes, sino la muestra de desarrollo (150) y el conjunto de evaluación.

## 6. Qué decide la IA y qué decide la persona

| Decide la IA | Decide el código | Decide la persona |
|---|---|---|
| Veredicto, confianza y argumentación | Severidad final (matriz y ajustes ±1), escalado obligatorio, verificación de autorizaciones, permisos de contención | Aprobar o rechazar la contención; confirmar el cierre o pasar a N2 |

- La IA nunca ejecuta una acción. Nunca se actúa sobre la red OT: solo se escala.
- Una autorización citada de palabra (en un correo o en el texto de la alerta) no basta: el código comprueba el cambio, su fecha y su origen.
- Todo texto de alertas y logs se trata como dato, no como instrucción. El dataset contiene 12 alertas con instrucciones ocultas para el sistema de triaje; probamos 6 de ellas (16 de 16 triajes correctos con repeticiones). Las otras 6 no están probadas.

## 7. Seguridad y privacidad

- La contención solo se ejecuta contra la API simulada y queda registrada con el nombre de quien aprueba.
- Los indicadores maliciosos reales del dataset no se visitan ni se escanean.
- La web no carga recursos de terceros y solo escucha en `127.0.0.1`.
- La clave del modelo vive en `.env`, fuera de git.
