# Nivel 3: investigación

- **Categoría:** IA + ciberseguridad (SOC)
- **Responsable:** todo el equipo TEMIPO
- **Estado:** 🟢 resuelto (mínimo viable, con límites claros)
- **Resultado:** informe válido contra `informe_incidente.schema.json` en los 4 incidentes probados, 10–15 s cada uno.

## Enunciado
Para lo que se escala: reconstruir la cadena de ataque, aunque dure días, con origen, alcance y relación con otros incidentes. Formato de referencia: `informe_incidente.schema.json`.

## Cómo lo resolvimos (`src/investigacion.py`)
1. **El código construye lo que se puede comprobar:**
   - los IDs de alerta del incidente (un grupo entero si la alerta forma parte de uno);
   - la **línea de tiempo**: las alertas y los eventos de log que citó el triaje, ordenados por hora. Cada ID existe en los datos; un evento que se inventase el modelo no entra;
   - el **alcance** (usuarios, equipos, servicios de negocio, clientes);
   - el **plan de contención**: las acciones del ticket con quién aprueba cada una; lo de la red OT sale como «solo escalar»;
   - las **notificaciones**: DPO y AEPD en 72 h si hay datos personales, Finanzas y banco si hay fraude, adquirente PCI, proveedor si es una cuenta `ext.*`, Operaciones si hay equipos OT, y el SLA de la severidad.
2. **El LLM solo redacta lo que pide interpretación:** paciente cero, acceso inicial, causa raíz, datos afectados, erradicación y recuperación, huecos de detección y preguntas abiertas. El expediente va marcado como datos no fiables y la salida es JSON validado (con un reintento si no cumple el formato).
3. **Comprobaciones después del modelo:** el informe se valida contra el esquema, y el código comprueba que el paciente cero sea un equipo, usuario, IP, cliente o identidad cloud que aparece en las alertas; si no, lo anota la primera en las preguntas abiertas.
4. **Relación con otros incidentes (`related_incidents`, código sin LLM; `incidentes_relacionados`):** se compara con todo lo que sigue siendo sospechoso tras el triaje (grupos, alertas escaladas y alertas en revisión, marcadas como «en revisión, sin escalar»). Dos casos se relacionan si comparten un equipo, usuario, IP, cliente o identidad cloud en sus alertas (aunque estén separados en el tiempo y la agrupación no los uniera), o si una entidad de uno aparece en un evento de log que reunió el triaje del otro. Cada relación cita la entidad y el ID del evento para que la persona lo compruebe. Con datos reales relaciona el túnel DNS desde WMS01 (`ALR-20261011-011883`) con el acceso VPN de madrugada de `ext.logisoft` (`ALR-20261011-011877`), que no comparten ninguna entidad en las alertas: el usuario del proveedor sale en el evento `EDR-0123433` (instala un servicio sin firmar en WMS01) y WMS01 en `FW-0026536` (RDP desde la VPN de Logisoft). Entre los 5 incidentes escalados de la demo no sale ninguna relación falsa.
5. **Solo para lo escalado:** el servidor lo comprueba (409 en caso contrario). El informe no ejecuta nada; la contención sigue necesitando a una persona.
6. **En la web:** panel «Informe de investigación · nivel 3» en el detalle, con botón de generar, todas las secciones (también «Relación con otros incidentes») y descarga del JSON.

## Pruebas con el LLM real
| Incidente | Alertas | Línea de tiempo | Confianza |
|---|---|---|---|
| Phishing de SSO → toma de cuenta y fraude de IBAN | 5 | 14 eventos | 0,85 |
| Malware Latrodectus en un portátil | 1 | 7 | 0,70 |
| Fraude con tarjeta regalo en la tienda online | 1 | 5 | 0,85 |
| Phishing con instrucciones ocultas para el sistema | 1 | 5 | 0,70 |

En el último, el informe ignora la instrucción oculta y la anota como hueco de detección.

## Lo que aprendimos
- La prueba con datos reales destapó un fallo de la comprobación del paciente cero: no reconocía clientes de la tienda ni identidades cloud. Arreglado y con test.
- Dejar la línea de tiempo al código evita el fallo típico de un LLM: inventarse eventos.

## Límites (a decir en la defensa)
- El informe llega solo hasta donde llegan las alertas **ya triadas**: el incidente de Latrodectus tiene 18 alertas en el dataset y solo una está triada, así que no ve el resto de la cadena.
- La línea de tiempo se limita a los eventos que reunió el triaje (±24 h por alerta); no rastrea el incidente por todos los logs.
- La relación con otros incidentes solo mira lo **ya triado** y los eventos que reunió el triaje: no busca en todo el dataset. Una entidad muy común (un controlador de dominio, la web de la tienda) podría relacionar dos casos que no tienen que ver; por eso cada relación dice el motivo y la decide la persona.
- El contenido (causa raíz, erradicación) lo redacta el modelo y lo hemos revisado leyéndolo; no lo ha validado un analista externo.
