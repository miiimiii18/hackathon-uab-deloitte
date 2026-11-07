# Revisión del gold set (propuesta para el equipo)

Etiquetas propuestas para 33 alertas de la muestra de desarrollo, **a partir de la evidencia** (API del SOC), no de lo que dice el LLM. Están en `evaluacion/casos.json` con `"revisado": false`.

**Qué hay que hacer:** leer cada fila y, si no estáis de acuerdo, cambiar `veredictos_validos` en `casos.json` (y poner `"revisado": true` en las que hayáis mirado). Las **3 marcadas con ⚠️** son las que más necesitan vuestra decisión.

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

## Casos con matices

| Alerta | Regla | Qué pasa | Propuesta |
|---|---|---|---|
| ALR-20261008-001417 | WEB-001 | Escaneo de `/.env` bloqueado **durante el pentest** (8 oct), pero desde una IP de hosting que **no es del pentest** (el cambio dice 192.0.2.10–12) | TP o FP, **nunca BTP** (trampa) |
| ALR-20261008-001415 | WEB-001 | Igual (PHPUnit, otra IP) | TP o FP, nunca BTP |
| ALR-20261014-003674 | EDR-003 | Fichero de prueba EICAR en Descargas, en cuarentena, no ejecutado; sandbox: limpio | FP o BTP |
| ALR-20261016-004912 | EDR-003 | Adware/PUA (WebCompanion) descargado por un DBA, en cuarentena, no ejecutado | TP (bloqueado) o NMI |
| ALR-20261014-003718 | EML-001 | Usuaria reporta el **simulacro de phishing** de RRHH (no hay cambio en el calendario) | BTP o FP |

## ⚠️ Necesitan decisión del equipo

| Alerta | Regla | Qué pasa | Propuesta |
|---|---|---|---|
| ALR-20261023-011915 | IDP-008 | `adm.aferrer` añade **`adm2.aferrer`** a Backup Operators desde JUMP01, dentro de la ventana del cambio CHG-2026-1078 («nuevo miembro del equipo de sistemas»). Pero `adm2.aferrer` **no existe en el directorio**, no hay evento de creación ni ninguna actividad, y parece una **segunda cuenta de la misma persona**, no un miembro nuevo | NMI o BTP. ¿Autorizado o tapadera? |
| ALR-20261101-010863 | CLD-003 | Bucket `tarvia-media-public` pasa a lectura pública por Terraform desde el runner de CI interno. Sin cambio en el calendario. Podría ser normal (es un bucket «público» de medios)… o un abuso del CI/CD | FP, BTP o NMI |
| ALR-20261007-001237 | DLP-001 | Una **analista de fraude** sube 825 MB de `fotos_campaña_navidad_RAW.zip` a WeTransfer; 0 datos personales | FP o NMI |

## Fallos de nuestro código que ha destapado esta revisión

1. **`evidencia.py` no busca los cambios que cita la propia alerta.** En `ALR-20261023-011915` la alerta trae `change_ticket: CHG-2026-1078` y la evidencia no lo encontró (solo busca por usuario, host, IP y dominio).
2. **`policy.py` no comprueba las IPs de origen del cambio.** El pentest (CHG-2026-1042) solo autoriza 192.0.2.10–12; un escaneo de otra IP en esas fechas no está autorizado, pero la política lo aceptaría si el LLM citara el cambio.
