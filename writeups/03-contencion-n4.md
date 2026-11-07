# Nivel 4: respuesta y contención con aprobación humana

- **Categoría:** IA + ciberseguridad (SOC)
- **Responsable:** todo el equipo TEMIPO
- **Estado:** 🟢 resuelto (mínimo viable)

## Enunciado
Proponer la contención y ejecutarla en la API simulada, siempre con aprobación humana.

## Cómo lo resolvimos
1. **El LLM sugiere, el código decide:** las acciones se construyen en `src/policy.py` (`permisos_accion`) a partir del veredicto. Define quién aprueba cada una (N1, N2, N2 + negocio, N2 + responsable del servicio). Si el veredicto no es TP ni `needs_more_info`, las acciones se descartan.
2. **N1 solo ejecuta** `purge_email` y `block_ioc`. Aislar, deshabilitar cuentas, revocar sesiones o desactivar claves se proponen y necesitan aprobación.
3. **Nunca en OT:** la política lo prohíbe y la API también lo rechaza. No se bloquean globalmente servicios de uso dual (mega.nz, AnyDesk) sin N2.
4. **Ejecución** (`src/contencion.py`): `POST /approvals` con el nombre de quien aprueba y después `POST /containment/{acción}` con el token. Sin aprobador no ejecuta nada. Limpia el objetivo que sugiere el LLM y bloquea los IOC de uno en uno. El resultado se guarda en `executed_actions` del ticket.
5. **En la web** (`src/web/`): «mantén pulsado para aprobar» con nombre, rechazar, confirmar cierre o pasar a N2. El servidor toma la acción de su copia del ticket: el navegador no puede cambiar `permitida`.

## Pendiente
- Nada para la demo. (La pantalla con el `containment_log` completo se hizo el 7-nov: `#/registro`.)

## Lo que aprendimos
- Separar «qué se propone» de «quién lo aprueba» evita que un texto malicioso lleve al sistema a actuar.
- Antes de la demo hay que borrar `containment_log.jsonl` para empezar con el registro vacío.
