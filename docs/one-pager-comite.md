# Triaje de alertas con IA para el SOC de Tarvia
**Resumen para el comité de dirección** · Equipo TEMIPO

## El problema
El equipo de seguridad de Tarvia recibe miles de alertas al mes (11.061 en cuatro semanas). La gran mayoría son falsas alarmas o actividad autorizada, pero entre ellas se esconden ataques reales. Revisarlas una a una cuesta horas de analista y el riesgo de dejar pasar una importante crece con la fatiga.

## Qué hace el piloto
Para cada alerta, el sistema hace lo que haría un analista de primer nivel:
1. Entiende qué ha pasado y consulta los datos de la empresa: equipos, personas, cambios aprobados, inteligencia sobre amenazas y registros.
2. Propone una conclusión: ataque real, actividad autorizada, falsa alarma o «necesito más información».
3. Calcula la gravedad con las reglas del SOC de Tarvia, no con la opinión de la IA.
4. Deja un resumen listo para que una persona decida: cerrar, revisar o pasar al equipo senior.

Cada paso queda visible en una pantalla: qué ha consultado, en qué se basa y qué propone.

## Qué decide la IA y qué decide una persona
| La IA | Las reglas de la empresa (programadas) | Una persona |
|---|---|---|
| Lee la evidencia, propone la conclusión y la explica | Fijan la gravedad, cuándo hay que avisar al equipo senior y qué acciones se pueden hacer | Aprueba o rechaza cualquier acción de contención y confirma cada cierre |

La IA **no ejecuta nada por su cuenta**. Aislar un equipo o desactivar una cuenta requiere siempre la aprobación de una persona con nombre, y en la red industrial nunca se actúa: solo se avisa.

## Qué aporta (medido en el piloto)
- **Rapidez:** unos 13 segundos por alerta; diez alertas en aproximadamente un minuto.
- **Coste:** cero, porque usa el modelo gratuito de la organización del reto.
- **Acierto:** en un conjunto de 42 casos que hemos revisado a mano acierta el 86 % de las conclusiones, el 89 % de las gravedades y el 90 % de las decisiones de cerrar, revisar o escalar. No se ha dejado engañar en ninguna de las 16 pruebas con instrucciones ocultas en correos y mensajes.
- **Explicación:** cada conclusión indica las fuentes y las reglas aplicadas, para que la persona pueda comprobarla.
- **Prudencia:** una actividad «autorizada» solo se acepta si existe el cambio aprobado, en esa fecha y desde ese origen. Una excusa escrita en el propio texto de la alerta no vale.

## Qué no resuelve
- El acierto es una estimación sobre pocos casos y sin revisión externa: puede equivocarse, y a veces da respuestas distintas ante la misma alerta. En las pruebas, algún ataque real se llegó a clasificar como falsa alarma en una de las repeticiones, y algunas falsas alarmas se escalaron: por eso una persona debe revisar también lo que el sistema propone cerrar.
- Agrupa en un solo caso las alertas relacionadas que están en la cola, pero no busca por su cuenta otras alertas del mismo ataque ni reconstruye su cronología completa.
- Depende de que el inventario y la inteligencia de amenazas estén al día. Un dato desconocido no se considera seguro.
- No se ha probado con el volumen real de un SOC (miles de alertas al día).
- No sustituye al analista: reduce el ruido y le entrega el caso preparado.

## Siguientes pasos propuestos
1. Revisión de las conclusiones por analistas de Tarvia para medir el acierto real.
2. Buscar automáticamente otras alertas relacionadas con cada caso y reconstruir su cronología.
3. Conectar con la inteligencia externa y probar con el volumen real.
4. Piloto en paralelo con el equipo humano antes de usarlo en producción.
