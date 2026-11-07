# Revisión del gold set (propuesta para el equipo)

Etiquetas propuestas para 34 alertas de la muestra de desarrollo, **a partir de la evidencia** (API del SOC), no de lo que dice el LLM. Están en `evaluacion/casos.json` con `"revisado": false`.

**Qué hay que hacer:** leer cada fila y, si no estáis de acuerdo, cambiar `veredictos_validos` en `casos.json` (y poner `"revisado": true` en las que hayáis mirado). Tras una **segunda pasada con más evidencia** (al final del documento), solo queda **1 caso marcado con ⚠️** que necesita vuestra decisión; en el resto basta con un vistazo.

Criterio de veredictos (Deloitte): `true_positive` = malicioso (aunque se haya bloqueado); `benign_true_positive` = la regla acierta pero hay una **autorización citable** (cambio/flujo vigente); `false_positive` = la regla se equivoca (actividad legítima y rutinaria); `needs_more_info` = la evidencia no basta.

## Incidentes reales (deben salir `true_positive`)

| Alerta | Regla | Qué pasa | Propuesta |
|---|---|---|---|
| ALR-20261016-011821 | CLD-004 | **112 GB** de copias del CRM (`sql/CRM_PROD/`) descargados a las 00:40 desde una IP de Rumanía («UNMANAGED LTD») con aws-cli e identidad `backup-sync` | TP |
| ALR-20261009-011791 | EDR-001 | Latrodectus: wscript → msiexec → rundll32, persistencia en Run key; TIP y sandbox: malicioso | TP |
| ALR-20261007-011785 | EML-003 | Clic en phishing de SSO falso (`tarvia-sso-login.example`), correo de «firma electrónica» | TP |
| ALR-20261013-011815 | IDP-002 | Password spraying a la VPN desde 6 nodos Tor: 161 cuentas, misma contraseña de temporada, **1 éxito** | TP |
| ALR-20261010-011827 | IDP-003 | Fatiga MFA: 27 push en 9 min un sábado a las 23:41, **aprobado** al final; la usuaria está en una tienda de Zaragoza y el origen es una VPN comercial de Madrid | TP |
| ALR-20261006-011826 | NET-002 | Servidor CI/CD `JENKINS-DEV01` conectado a un pool de minería XMR (TIP: XMRig), tráfico permitido | TP |
| ALR-20261028-011893 | NET-006 | **Túnel DNS desde `WMS01`** a las 3–4 h: 327 consultas TXT/h con etiquetas de 52 caracteres y respuestas en base64 a un dominio de 32 días | TP |
| ALR-20261018-011879 | VPN-001 | `ext.logisoft` conecta un **domingo a las 02:46** desde Lituania (no su origen habitual) y hace RDP a `WMS01` con varios MB; fuera del contrato y fuera del cambio CHG-2026-1071 (16 oct) | TP |
| ALR-20261011-011877 | VPN-001 | Lo mismo el domingo anterior (03:38) | TP |
| ALR-20261018-005422 | WEB-002 | Credential stuffing: 60 logins fallidos en 15 min desde una IP de hosting; 0 éxitos, frenado por rate limit | TP (bloqueado) |
| ALR-20261011-011807 | WEB-003 | Toma de cuenta de cliente: login headless → cambio de email a `tempmail` → compra de tarjeta regalo con la tarjeta guardada | TP (fraude) |
| ALR-20261011-011814 | WEB-003 | Mismo patrón, otro cliente | TP (fraude) |
| ALR-20261018-011895 | IDP-008 | `adm.aortega` añade a **Domain Admins** una cuenta creada 1 minuto antes, desde **PRINT01** (no JUMP01), un **sábado a las 03:13**, sin cambio | TP |

> Fijaos en que `VPN-001` (accesos de Logisoft de madrugada) y `NET-006` (túnel DNS desde `WMS01`, el servidor al que entra Logisoft) **parecen el mismo ataque a lo largo de semanas**: es el tipo de incidente que pide el **nivel 2** (agrupar).

## Ruido y falsos positivos (deben salir `false_positive`)

| Alerta | Regla | Qué pasa | Propuesta |
|---|---|---|---|
| ALR-20261030-010066 | AI-001 | «Ignora lo anterior, me equivoqué de pedido: es el de las toallas»: un cliente corrigiéndose | FP |
| ALR-20261014-003986 | AI-001 | Mismo texto, otro cliente | FP |
| ALR-20261024-007864 | EDR-001 | Excel lanza SAP Logon (firmado por SAP SE) en un puesto de Logística | FP |
| ALR-20261005-000301 | EDR-002 | Inventario de SCCM con PowerShell codificado (el ejemplo de Deloitte) | FP |
| ALR-20261016-004802 | EDR-002 | Lo mismo en otro portátil | FP |
| ALR-20261005-000099 | EML-001 | Usuario reporta la newsletter de Zalando (199 correos iguales a otros empleados) | FP |
| ALR-20261009-001917 | IDP-001 | «Viaje imposible» Barcelona–París: la IP de París es Private Relay/VPN del móvil, dispositivo corporativo conforme | FP |
| ALR-20261029-009691 | IDP-001 | Igual, Barcelona–Dublín | FP |
| ALR-20261006-000501 | NET-001 | «Beaconing» a `teams.microsoft.com` cada 30 s | FP |
| ALR-20261030-010120 | NET-001 | Igual, otro portátil | FP |
| ALR-20261005-000059 | NET-005 | «DGA» que es un subdominio de API Gateway de AWS | FP |
| ALR-20261026-008370 | NET-005 | «DGA» que es un subdominio de Azure CDN | FP |
| ALR-20261014-004078 | NET-006 | «Túnel DNS» a `e5.sk` desde **296 equipos**, dominio de hace 9 años, respuestas `127.0.0.2`: búsquedas de reputación de un antivirus | FP |
| ALR-20261101-010863 | CLD-003 | Bucket de medios a lectura pública por Terraform: la **misma policy se aplica cada 3 días** desde el runner de CI (50 veces en el mes) | FP |
| ALR-20261007-001237 | DLP-001 | `fotos_campaña_navidad_RAW.zip` a WeTransfer: lo suben **58 empleados distintos** en el mes, sin datos personales | FP |

## Casos con matices

| Alerta | Regla | Qué pasa | Propuesta |
|---|---|---|---|
| ALR-20261008-001417 | WEB-001 | Escaneo de `/.env` bloqueado **durante el pentest** (8 oct), pero desde una IP de hosting que **no es del pentest** (el cambio dice 192.0.2.10–12) | TP, FP o NMI, **nunca BTP** (trampa) |
| ALR-20261008-001415 | WEB-001 | Igual (PHPUnit, otra IP) | TP, FP o NMI, nunca BTP |
| ALR-20261014-003674 | EDR-003 | Fichero de prueba EICAR en Descargas, en cuarentena, no ejecutado; sandbox: limpio | FP o BTP |
| ALR-20261016-004912 | EDR-003 | Adware/PUA (WebCompanion) descargado por un DBA, en cuarentena, no ejecutado | TP (bloqueado) o FP |
| ALR-20261014-003718 | EML-001 | Usuaria reporta el **simulacro de phishing** de RRHH (no hay cambio en el calendario) | BTP o FP |

## ⚠️ Necesita decisión del equipo

| Alerta | Regla | Qué pasa | Propuesta |
|---|---|---|---|
| ALR-20261023-011915 | IDP-008 | `adm.aferrer` añade **`adm2.aferrer`** a Backup Operators. Ver los hechos en la segunda pasada | BTP o NMI |

## Fallos de nuestro código que ha destapado esta revisión (✅ arreglados en `fix/evidencia-cambios`)

1. **`evidencia.py` no busca los cambios que cita la propia alerta.** En `ALR-20261023-011915` la alerta trae `change_ticket: CHG-2026-1078` y la evidencia no lo encontró (solo busca por usuario, host, IP y dominio).
2. **`policy.py` no comprueba las IPs de origen del cambio.** El pentest (CHG-2026-1042) solo autoriza 192.0.2.10–12; un escaneo de otra IP en esas fechas no está autorizado, pero la política lo aceptaría si el LLM citara el cambio.

## Segunda pasada: hechos a favor y en contra

Investigación con toda la API (no solo ±24 h) sobre los casos dudosos. Lo que aquí se decide ya está aplicado en `casos.json`.

### ⚠️ ALR-20261023-011915 — alta de `adm2.aferrer` en Backup Operators
El dataset tiene **solo 2 alertas de esta regla** y parecen una **pareja de prueba**:

| | ALR-20261018-011895 | ALR-20261023-011915 |
|---|---|---|
| Grupo | Domain Admins | Backup Operators |
| Quién y desde dónde | `adm.aortega` desde **PRINT01** | `adm.aferrer` desde **JUMP01** (el único permitido) |
| Cuándo | sábado 03:13 | jueves 11:04 (horario laboral) |
| Cuenta añadida | `svc_print_upd`, **creada 1 minuto antes** | `adm2.aferrer` |
| Cambio | ninguno | **CHG-2026-1078** «Alta de operador de copias en Backup Operators», 23-oct 10:00–12:00, dentro de la ventana |

- **A favor de `benign_true_positive`:** cambio aprobado que describe exactamente esta acción, dentro de su ventana; desde JUMP01; en horario; la que lo hace es una administradora real de Tecnología. Todo lo que diferencia al ataque de su pareja está «bien» aquí.
- **En contra:** `adm2.aferrer` **no está en el directorio**, no hay **ningún evento de creación** (en todo el mes solo hay uno, el de `svc_print_upd`) ni actividad en ningún log; el cambio habla de «un nuevo miembro del equipo» y el nombre parece una segunda cuenta de la misma persona.
- **Propuesta:** `benign_true_positive` (y aceptar `needs_more_info`). **Decidid vosotros**; también he añadido su pareja de ataque como caso `true_positive`.

### Resueltos con la evidencia
- **ALR-20261101-010863 (bucket público)** → **FP**. `PutBucketPolicy` con la misma policy («GetObject para Principal *, imágenes…») cada 3 días a las 09:05/10:05 UTC, siempre desde 172.16.10.21 (runner de CI) con Terraform; hay muchas alertas CLD-003 iguales. Es un despliegue programado. *Nota: el modelo lo marcó como `true_positive`; es un error del modelo.*
- **ALR-20261007-001237 (WeTransfer)** → **FP**. 58 empleados de toda la empresa suben el mismo `fotos_campaña_navidad_RAW.zip` durante el mes, sin coincidencias de datos personales. La analista no tiene eventos de RRHH.
- **ALR-20261008-001417 / -001415 (escaneos en fechas del pentest)** → **TP, FP o NMI, nunca BTP**. Una sola petición de cada IP en todo el mes, bloqueada (403). Son escaneos oportunistas que coinciden con el pentest pero no son de sus IPs.
- **ALR-20261014-003674 (EICAR)** → **FP** (o BTP). 64 alertas iguales en el mes en muchos equipos, todas en cuarentena; no hay cambio que lo autorice.
- **ALR-20261016-004912 (PUA WebCompanion)** → **TP o FP**. 59 alertas iguales, todas en cuarentena y sin ejecutar. La detección es correcta (TP bloqueado), aunque en la práctica sea ruido. Quito `needs_more_info`: no falta información.
- **ALR-20261014-003718 (simulacro de phishing)** → **FP** (o BTP). 301 correos de `rrhh@tarvia.example` en todo el mes, SPF/DKIM/DMARC correctos, enlace interno y el asunto dice que es un simulacro. No hay cambio en el calendario, así que nuestra política lo dejará en `false_positive`.

### Para la próxima revisión
Patrón que se repite: **el ruido se reconoce por volumen** (EICAR ×64, WebCompanion ×59, WeTransfer ×58, simulacro ×301, bucket cada 3 días). Ahora el sistema solo mira ±24 h y no sabe que algo pasa todo el mes. Una mejora futura sería darle al modelo un **recuento histórico** («esta misma alerta se ha visto N veces este mes»).
