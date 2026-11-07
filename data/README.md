# Datos

Esta carpeta está ignorada por git (excepto este archivo). Cada persona descarga aquí los datos del reto.

| Carpeta / archivo | Fuente | Notas |
|---|---|---|
| `tarvia/` | Repo de Deloitte [`dttdfr/DTT-UAB-The-Hack`](https://github.com/dttdfr/DTT-UAB-The-Hack) (clonado; último commit al prepararlo: `5d75692` «Adding PPT», 6-nov-2026) | Dataset sintético del SOC de Tarvia: 11.061 alertas, 814.471 eventos de 18 logs, inventario, inteligencia y la API simulada (`06_herramientas/mock_soc_api.py`). Unos 270 MB. |
| `tarvia/06_herramientas/containment_log.jsonl` | Lo escribe la API simulada | Registro de las acciones de contención (simuladas). Borrarlo lo reinicia (p. ej., antes de la demo). |
| `out/` | Lo generamos nosotros | Resultados de triajes (`python -m src.triaje ... --salida data/out/...`) y evaluaciones (`python -m scripts.evaluar`). Se puede borrar y regenerar. |

Para tenerlo (desde la raíz del proyecto):

```bash
git clone https://github.com/dttdfr/DTT-UAB-The-Hack.git data/tarvia   # una sola vez
git -C data/tarvia pull                                                  # para actualizarlo
```

**Ojo:** parte de los indicadores del dataset (IPs, dominios, hashes) son maliciosos **reales**. Solo se consultan en servicios de reputación; nunca se visitan, descargan ni escanean.
