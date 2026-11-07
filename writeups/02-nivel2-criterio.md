# Nivel 2: triaje con criterio

- **Categoría:** IA + ciberseguridad (SOC)
- **Responsable:** todo el equipo TEMIPO
- **Estado:** 🟡 parcial (matriz y descarte de autorizaciones hechos; agrupación pendiente)
- **Resultado:** autorizaciones 15/15 y matices 9/9 en el gold set; ningún ataque inventado se cierra como falso positivo.

## Enunciado
Agrupar alertas del mismo ataque, aplicar la matriz de severidad con la criticidad real del activo y descartar con argumentos la actividad autorizada.

## Lo hecho
1. **Matriz de severidad** (`src/policy.py`): regla × criticidad del activo más crítico de la CMDB (sin activo, la del servicio: WAF/ECOM Crítica, AI_GATEWAY Alta, si no Media). Ajuste total de ±1: +1 por ejecución confirmada, VIP/privilegiado (del directorio, no del LLM) o datos personales/pagos; −1 si un control lo bloqueó sin actividad posterior. Falso positivo → `informational`.
2. **Actividad autorizada con prueba:** `benign_true_positive` solo si el veredicto cita un cambio o flujo (`CHG-…`, `FLUJO-…`) presente en la evidencia, cuya ventana de fechas cubra la alerta y cuyo origen coincida. También reglas internas de Tarvia (`svc_backup`, TeamViewer, `ext.logisoft` L–V 8–18 h, escáner `NESSUS01`).
3. **Autorización que no encaja = sospecha:** otra fecha u otra IP (p. ej. el escaneo del 8-oct desde una IP que no es del pentest) pasa a `needs_more_info`, porque puede ser una tapadera.
4. **Reglas duras:** equipos que hablan con OT distintos de ENG-WS01/WMS01 y cuentas `adm.*` fuera de JUMP01 no se pueden cerrar sin cambio verificado.
5. **Escalado obligatorio** a N2 con sus motivos: TP high/critical, ejecución confirmada, datos personales o pagos, fraude.

## Pendiente
- Deduplicar (~920 alertas exactas repetidas) y agrupar alertas por entidades compartidas en un único ticket, incluidas las de días o semanas distintas.

## Lo que aprendimos
- Citar un cambio de palabra no basta: el texto lo puede escribir el atacante.
- La revisión del gold set destapó 2 fallos de código (cambio citado en la alerta no buscado; IPs de origen del cambio no comprobadas) y los arreglamos.
- La robustez frente a datos raros se probó con 9 alertas inventadas; una con campos mal formados rompía el triaje y se arregló con `normalizar_alerta()`.
