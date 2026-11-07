# Lo que esta solución no resuelve

Documento para la defensa y base del panel «Lo que no resuelve» de la web. Las cifras salen de `evaluacion/` y de `docs/plan-de-trabajo.md` (medidas el 7-nov-2026).

## 1. No sabemos con certeza cuánto acertamos

- Las alertas del dataset **no traen la respuesta correcta**. Medimos contra 42 alertas etiquetadas por nosotros (`evaluacion/casos.json`), más 9 inventadas.
- Esas etiquetas las ha revisado Claude con una segunda pasada de evidencia; **no hay revisión humana independiente**.
- Resultado: 107 de 126 triajes correctos (85 %), con 42 casos repetidos 3 veces. Incidentes 77 %, ruido 78 %. Es una estimación sobre un conjunto pequeño, no una garantía.
- Solo medimos el **veredicto**. Todavía no medimos con el mismo rigor si la severidad final y el escalado son los esperados.

## 2. La IA se equivoca y no siempre da la misma respuesta

- 8 de los 42 casos dieron veredictos distintos entre repeticiones.
- Fallos que se repiten:
  - Accesos de un proveedor externo de madrugada y fuera de horario: la IA los deja en «necesita más información» en vez de marcarlos como ataque.
  - Un «túnel DNS» que en realidad es un antivirus consultando reputación: la IA lo da por ataque.
- Por eso la severidad, el escalado y los permisos **no los decide la IA**: están en código con tests, y una persona aprueba toda acción que no sea de bajo riesgo.
- Un triaje falló por tiempo (más de 300 s) porque el servidor de modelos es compartido con los demás equipos.

## 3. Depende de la calidad de los datos

- Un indicador que la inteligencia interna no conoce se trata como **desconocido, no como limpio**: baja la confianza, pero no demuestra nada.
- Si un equipo o un usuario no aparece en el inventario, el sistema sigue y lo anota, pero la severidad se calcula con valores por defecto.
- No consultamos servicios de reputación externos (VirusTotal, AbuseIPDB…). Solo usamos la inteligencia interna del dataset.
- La búsqueda de contexto en los registros se limita a ±24 h alrededor de la alerta. Una causa anterior a esa ventana no se ve.

## 4. Lo que el sistema todavía no hace

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
