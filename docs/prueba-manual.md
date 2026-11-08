# Prueba manual de la web

Recorrido de principio a fin para comprobar la web antes de la defensa. Dura unos 20–25 minutos. Cada paso dice qué hacer (→) y qué debería salir (✅). Comprobada el 8-nov con Playwright y Chrome.

**La prueba ensucia los resultados guardados:** guarda decisiones humanas en las alertas, añade alertas a la cola y deja acciones en el registro de contención. El paso 14 lo deja todo limpio; no te lo saltes antes de la defensa.

## 0. Preparación
1. → Arranca la API del SOC y la web como dice [`arrancar.md`](arrancar.md) y abre http://127.0.0.1:8080.
2. → Crea `data/prueba.jsonl` con 4 alertas (dos duplicadas y la pareja Logisoft/WMS01). Desde la raíz del proyecto:
   ```powershell
   .venv\Scripts\python -c "import json; ids={'ALR-20261005-000211','ALR-20261005-000021','ALR-20261011-011877','ALR-20261011-011883'}; open('data/prueba.jsonl','w',encoding='utf-8').writelines(l for l in open('data/tarvia/03_alertas/alertas.jsonl',encoding='utf-8') if l.strip() and json.loads(l)['alert_id'] in ids)"
   ```
3. → Crea `data/sso5.jsonl` con las 5 alertas del phishing de SSO (se usa en el paso 7):
   ```powershell
   .venv\Scripts\python -c "import json; ids={'ALR-20261007-011785','ALR-20261007-011786','ALR-20261007-011787','ALR-20261007-011788','ALR-20261008-011789'}; open('data/sso5.jsonl','w',encoding='utf-8').writelines(l for l in open('data/tarvia/03_alertas/alertas.jsonl',encoding='utf-8') if l.strip() and json.loads(l)['alert_id'] in ids)"
   ```

## 1. Cabecera y estado
- [ ] ✅ No hay avisos rojos, se ven los chips «API del SOC» y del modelo y el enlace «Registro de contención».
- [ ] → Para la API del SOC (Ctrl+C) y recarga la página. ✅ Sale un aviso rojo con el comando de `uvicorn`. → Vuelve a arrancar la API y recarga. ✅ El aviso desaparece.

## 2. Cola de alertas
- [ ] ✅ Aparecen las 10 alertas de la cola, con su severidad, veredicto y decisión si ya estaban triadas.
- [ ] → Pulsa «Triar las N». ✅ Cada fila avanza por Evidencia → IA → Política y acaba con su sello, con contador de segundos. Tarda ~1 min (43 s medidos).
- [ ] → Filtros: prueba cada desplegable (regla, severidad, veredicto y estado). ✅ El contador «N de M a la vista» cambia. → «Quitar filtros». ✅ Vuelven todas.
- [ ] → Pon un filtro, entra en una alerta y vuelve a la cola. ✅ El filtro se conserva.
- [ ] ✅ La franja «Lo que no resuelve» aparece en la cola.
- [ ] ✅ Si en la cola no hay alertas del phishing de SSO, el subtítulo no dice «ataque agrupado».

## 3. Alerta de ruido (`ALR-20261005-000301`)
- [ ] → Entra en la alerta. ✅ Se ven las tres tarjetas **IA propone / Código decide / Persona decide**.
- [ ] ✅ Panel «Qué ha consultado» (la traza) y panel «En qué se basa».
- [ ] ✅ «Alerta original» muestra el JSON. → Abre «Ver datos en bruto». ✅ Se ve el JSON.
- [ ] ✅ La política dice `false_positive`, `informational` y cerrar, con la explicación de la severidad.
- [ ] → «Confirmar cierre» **sin nombre**. ✅ Lo rechaza. → Con nombre. ✅ Queda anotado («Cierre confirmado por…»).

## 4. Autorización que no encaja (`ALR-20261008-001417`)
- [ ] ✅ Sale `needs_more_info` y «Revisar». El aviso (en rojo, porque el código corrige a la IA) explica que CHG-2026-1042 solo autoriza 192.0.2.10–12 y la alerta viene de 198.18.46.60.
- [ ] → «Pasar a N2» con nombre. ✅ Queda anotado.

## 5. Actividad autorizada (`ALR-20261008-011833` y `ALR-20261023-011915`)
- [ ] ✅ Salen `benign_true_positive`, severidad baja y cerrar, citando el cambio verificado (CHG-2026-1042 y CHG-2026-1078).

## 6. Incidente con contención (`ALR-20261009-011791`, Latrodectus)
- [ ] ✅ Sale crítica y escalada, con la cuenta (regla × activo ± ajuste) y los motivos de escalado.
- [ ] → En una acción de N2 (`isolate_host`, `revoke_sessions`...) sin nombre. ✅ El botón está deshabilitado. → Escribe «N2 - Tu nombre». → Pulsa menos de 1 s. ✅ No ejecuta. → **Mantén pulsado** más de 1 s. ✅ Se ejecuta y aparece en `executed_actions`.
- [ ] → En una acción del N1 (`block_ioc`, `purge_email`) pulsa «Ejecutar». ✅ Se ejecuta sin pedir nombre.
- [ ] → En otra acción, «Rechazar». ✅ Queda marcada como rechazada.
- [ ] ✅ Las acciones ya ejecutadas o rechazadas no tienen botones.
- [ ] → «Ticket JSON». ✅ Descarga el ticket.

## 7. Agrupación e informe N3 (phishing de SSO)
- [ ] → «Cargar alertas» → pestaña «Subir archivos» → «Elegir archivos» → `data/sso5.jsonl` → «Cargar y triar». ✅ Las 5 llevan «Mismo ataque · 5 alertas».
  *(También vale la pestaña «Del dataset»: con texto busca en las 11.061 alertas; sin texto lista la muestra de 150.)*
- [ ] → Entra en una. ✅ Panel «Mismo ataque» con las 5 alertas enlazadas (pulsa una) y «Ticket único JSON».
- [ ] ✅ Panel «Informe de investigación · nivel 3». Si no existe, «Generar informe de investigación» (~15 s).
- [ ] ✅ El informe tiene paciente cero, acceso inicial, línea de tiempo con IDs de evento, alcance, causa raíz, relación con otros incidentes, plan de contención, erradicación, a quién avisar, huecos de detección, preguntas abiertas y «Cumple el esquema de Deloitte». → «Informe JSON» lo descarga.
- [ ] → Entra en una alerta cerrada (`ALR-20261005-000301`). ✅ No sale el panel del informe.

## 8. Prompt injection (`ALR-20261020-011905`)
- [ ] ✅ Sale escalada y el resumen de la IA describe el fragmento oculto que intenta que se marque como `false_positive`, sin obedecerlo.

## 9. Corrección humana (`ALR-20261007-001237`, fotos a WeTransfer)
- [ ] ✅ Es el falso positivo conocido. El modelo es inestable: unas veces sale `false_positive` y otras ataque crítico.
- [ ] → «No estoy de acuerdo: corregir el veredicto» → «Registrar corrección» sin motivo ni nombre. ✅ Lo rechaza. → Con `false_positive`, `informational`, motivo y nombre. ✅ Queda anotado, la cola muestra «Persona: …» y **lo que calculó el código no cambia**.

## 10. Cargar alertas nuevas
- [ ] **Completa:** «Pegar JSON» con el contenido de `evaluacion/alertas_inventadas/INV-01-fraude-iban-cfo.json`. ✅ Los cinco campos con ✓. → «Cargar y triar». ✅ Se tría en directo.
- [ ] **Pobre:** `{"rule_id": "UC-EDR-002", "entities": {"hosts": ["WS-BCN-1174"]}}`. ✅ `alert_id` en amarillo («se asigna ALR-MANUAL-…») y también `severity` y `created_at`. → Tríala. ✅ El detalle avisa de lo que se completó (ID, severidad y runbook del catálogo, sin hora).
- [ ] **Inválida:** `{"severity": "high"}`. ✅ Rojo «no trae nada que investigar» y botones desactivados. `hola` → «Línea 1: no es JSON válido».
- [ ] **Lista:** `[ {...}, {...} ]`. ✅ Valida cada una por separado.
- [ ] **Subir fichero:** «Subir archivos» → `data/prueba.jsonl`. ✅ 4 alertas válidas. → «Cargar y triar».
  - ✅ **Deduplicación:** `ALR-20261005-000021` lleva «Duplicada de ALR-20261005-000211» y el mismo resultado, sin otra llamada al LLM.
  - ✅ **Relación entre incidentes:** entra en `ALR-20261011-011883` (túnel DNS, escalado) y genera el informe. «Relación con otros incidentes» lista `ALR-20261011-011877 (en revisión, sin escalar)` con los eventos `EDR-0123433` y `FW-0026536`.
- [ ] → «Cargar en la bandeja» con cualquier alerta. ✅ Entra sin triar («En cola»). → Entra en ella. ✅ Sale «Triar esta alerta».

## 11. Registro de contención
- [ ] → Chip «Registro de contención». ✅ Están las acciones del paso 6 con hora, acción, objetivo, ticket, quién aprobó (nombre), token y resultado. → «Actualizar».

## 12. Plan B
- [ ] → Para **solo la API del SOC** (la web sigue) y recarga. ✅ Las alertas ya triadas se siguen abriendo (detalle, grupo, informe). El registro de contención muestra «No se pudo leer el registro…» pasados unos segundos.
- [ ] → Vuelve a arrancar la API del SOC.

## 13. Persistencia
- [ ] → Recarga (F5). ✅ La cola y los filtros de la cola se mantienen (los filtros solo en esa pestaña: si la cierras, se pierden).
- [ ] → «Vaciar». ✅ La bandeja queda vacía. → Carga un JSON con varias alertas. ✅ Solo están esas (sustituyen a las anteriores).

## 14. Limpieza (obligatoria antes de la defensa)
Para la web (Ctrl+C) y, desde la carpeta del proyecto:
```powershell
Remove-Item data\out\web -Recurse -Force
Remove-Item data\tarvia\06_herramientas\containment_log.jsonl -ErrorAction SilentlyContinue
Remove-Item data\prueba.jsonl, data\sso5.jsonl -ErrorAction SilentlyContinue
```
Vuelve a arrancar la web y después:
```powershell
.venv\Scripts\python -m scripts.preparar_demo --informe
```
Tarda ~1 min. Por último, en la web (en el navegador que vayas a usar en la demo) pulsa «Vaciar». Debe quedar con 15 resultados, sin decisiones de prueba y con el registro vacío.
