# Nivel 2: triaje con criterio

- **Categoría:** IA + ciberseguridad (SOC)
- **Responsable:** todo el equipo TEMIPO
- **Estado:** 🟢 resuelto en lo esencial (matriz, descarte de autorizaciones y agrupación); la deduplicación automática y la búsqueda de alertas relacionadas fuera de la cola quedan pendientes
- **Resultado:** autorizaciones 15/15 y matices 9/9 en el gold set; ningún ataque inventado se cierra como falso positivo.

## Enunciado
Agrupar alertas del mismo ataque, aplicar la matriz de severidad con la criticidad real del activo y descartar con argumentos la actividad autorizada.

## Lo hecho
1. **Matriz de severidad** (`src/policy.py`): regla × criticidad del activo más crítico de la CMDB (sin activo, la del servicio: WAF/ECOM Crítica, AI_GATEWAY Alta, si no Media). Ajuste total de ±1: +1 por ejecución confirmada, VIP/privilegiado (del directorio, no del LLM) o datos personales/pagos; −1 si un control lo bloqueó sin actividad posterior. Falso positivo → `informational`.
2. **Actividad autorizada con prueba:** `benign_true_positive` solo si el veredicto cita un cambio o flujo (`CHG-…`, `FLUJO-…`) presente en la evidencia, cuya ventana de fechas cubra la alerta y cuyo origen coincida. También reglas internas de Tarvia (`svc_backup`, TeamViewer, `ext.logisoft` L–V 8–18 h, escáner `NESSUS01`).
3. **Autorización que no encaja = sospecha:** otra fecha u otra IP (p. ej. el escaneo del 8-oct desde una IP que no es del pentest) pasa a `needs_more_info`, porque puede ser una tapadera.
4. **Reglas duras:** equipos que hablan con OT distintos de ENG-WS01/WMS01 y cuentas `adm.*` fuera de JUMP01 no se pueden cerrar sin cambio verificado.
5. **Escalado obligatorio** a N2 con sus motivos: TP high/critical, ejecución confirmada, datos personales o pagos, fraude.

## Agrupación (`src/agrupar.py`)
1. **Qué une dos alertas:** una entidad en común (usuario, equipo, IP, dominio, hash, cliente, identidad cloud, `message_id`) y cercanía en el tiempo: 30 días si es una cuenta o un equipo (un compromiso dura semanas), 3 días si es IP, dominio o hash (se reutilizan por casualidad).
2. **Qué evita fusionar todo:** las entidades que aparecen en más de 12 alertas se ignoran, y solo se agrupan las alertas que tras el triaje son `true_positive` o `needs_more_info`. Sin ese filtro, las reglas de mucho ruido unen todas las alertas de un mismo usuario.
3. **Un ticket por grupo** (`consolidar_grupo`): `alert_ids` de todo el grupo, la mayor severidad de sus alertas (sin sumar otro ajuste, para no pasar del ±1 total), escalado obligatorio por cadena de ataque (`decision_de_grupo` en `src/policy.py`) y acciones sin repetir.
4. **Prueba con el dataset completo:** quitando las 9 reglas ruidosas como sustituto del triaje, salen 22 grupos de 2 a 18 alertas que corresponden a incidentes reales (cadena de Latrodectus, accesos de un proveedor externo, túnel DNS, toma de cuenta de clientes, phishing de SSO).
5. **Prueba de extremo a extremo:** 5 alertas del phishing de SSO triadas con el LLM dan 1 ticket crítico escalado y válido contra el esquema.

## Pendiente
- Conectar `deduplicar()` (quita las ~920 alertas exactas repetidas) a la carga de alertas, y buscar alertas relacionadas fuera de la cola.

## Lo que aprendimos
- Citar un cambio de palabra no basta: el texto lo puede escribir el atacante.
- La revisión del gold set destapó 2 fallos de código (cambio citado en la alerta no buscado; IPs de origen del cambio no comprobadas) y los arreglamos.
- La robustez frente a datos raros se probó con 9 alertas inventadas; una con campos mal formados rompía el triaje y se arregló con `normalizar_alerta()`.
