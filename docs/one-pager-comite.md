# Triaje de alertas con IA para el SOC de Tarvia
**Resumen para el comité de dirección** · Equipo TEMIPO

## El problema
El SOC de Tarvia recibe unas 4.000 alertas al día y un analista tarda unos 15 minutos en cada una. El equipo trabaja de 8 a 20 h entre semana: de noche y en fin de semana nadie mira la consola. En cuatro semanas de datos (11.061 alertas) la gran mayoría es ruido o actividad autorizada, pero hay ataques reales escondidos, y la mitad de los que identificamos solo se entienden juntando alertas de varios días.

## Lo que hemos construido: el piloto
Para cada alerta, el sistema hace lo que haría un analista de primer nivel: consulta los datos de la empresa (equipos, personas, cambios aprobados, inteligencia sobre amenazas y registros), propone una conclusión, calcula la gravedad con las reglas del SOC y deja el caso listo para que una persona decida. Cada paso queda visible en pantalla.

| La IA | Las reglas de la empresa (programadas) | Una persona |
|---|---|---|
| Lee la evidencia, propone la conclusión y la explica | Fijan la gravedad, cuándo avisar al equipo senior y qué acciones se permiten | Aprueba toda acción de contención y confirma cada cierre |

La IA **no ejecuta nada por su cuenta**, y en la red industrial nunca se actúa: solo se avisa.

**Medido en el piloto:** unos 13 segundos por alerta (diez en un minuto); coste cero con el modelo gratuito de la organización del reto; entre el 80 y el 86 % de conclusiones correctas y entre el 87 y el 90 % de decisiones (cerrar, revisar o escalar) en 42 casos revisados por nosotros; 16 de 16 pruebas superadas con instrucciones ocultas para engañar a la IA.

## Cómo lo llevaría Deloitte a producción
Además del piloto, hemos diseñado la versión de producción y la hemos medido sobre las 11.061 alertas:

1. **Primero, quitar el ruido que tiene una explicación comprobable** (el inventario de software, ataques web ya bloqueados, cambios aprobados): es el 78 % de las alertas. La IA solo trabaja con el resto, y una persona confirma los cierres en bloque.
2. **Vigilar cada usuario, equipo y proveedor durante semanas, no solo un día.** Una puntuación de riesgo combina lo rara que es cada alerta con su contexto (horario, cuenta de proveedor o de administrador, empleado que deja la empresa). En nuestro estudio señaló los 12 incidentes que identificamos con 6 falsas alarmas, frente a 744 si se revisara toda alerta de gravedad alta; incluye un ataque lento de 18 días sin ninguna alerta grave.
3. **Dos modelos de IA abiertos, en servidores de Deloitte, sin que ningún dato salga.** Uno pequeño lee todas las alertas; uno grande revisa los casos difíciles sin ver la primera opinión, y cada día revisa al azar un 5 % de lo que el pequeño resolvió solo para medir sus errores invisibles. Recomendamos gpt-oss-20b y gpt-oss-120b (licencia abierta Apache 2.0).
4. **Lo urgente primero, las 24 horas.** Una cola ordenada por los plazos de la política (15 minutos para lo crítico), con los modelos siempre cargados; si un plazo crítico peligra, se avisa al analista de guardia.
5. **El hardware no se fija de antemano.** Un día de calibración en los servidores que Deloitte asigne decide cuántas copias de cada modelo hacen falta. Con la carga medida (unas 170 lecturas de la IA por cliente cada cuatro semanas, tras agrupar las campañas de phishing), una copia de cada modelo y una de reserva deberían bastar para muchos clientes como Tarvia.

## Qué no resuelve
- El acierto del piloto es una estimación sobre pocos casos, sin revisión externa, y varía entre ejecuciones. Una vez llegó a cerrar un ataque; lo corregimos con reglas fijas, pero no podemos garantizar que no vuelva a pasar. Por eso una persona confirma también los cierres.
- El piloto solo agrupa alertas ya analizadas y mira un día alrededor de cada una; el diseño de producción lo amplía, pero aún no está construido.
- Las cifras del diseño de producción son optimistas (las ajustamos viendo los incidentes) y no se han probado con el volumen real; el par de modelos recomendado no se ha probado porque no teníamos GPU.
- Depende de que el inventario y la inteligencia estén al día: un dato desconocido no se considera seguro.
- No sustituye al analista: reduce el ruido y le entrega el caso preparado.

## Siguientes pasos propuestos
1. Revisión de las conclusiones por analistas de Tarvia para medir el acierto real.
2. Construir el filtro de ruido y la vigilancia por semanas sobre el piloto.
3. Calibrar el par de modelos en los servidores de Deloitte y probar con el volumen real.
4. Piloto en paralelo con el equipo humano antes de usarlo en producción.
