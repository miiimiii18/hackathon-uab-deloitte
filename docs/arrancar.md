# Cómo arrancar la web en cualquier ordenador

Guía para Windows con PowerShell, que es lo que usamos en el equipo. Comprobada el 7-nov en un ordenador limpio.

## 1. Requisitos (una sola vez)
- **Python 3.11 o superior** y **Git**.
- **Acceso al repo privado** `miiimiii18/hackathon-uab-deloitte` en GitHub.
- **La clave del LLM del equipo**, pasada por un canal privado. **Nunca por git ni por el chat.**

## 2. Preparar el proyecto (una sola vez, unos 5 minutos)
```powershell
git clone https://github.com/miiimiii18/hackathon-uab-deloitte.git
cd hackathon-uab-deloitte
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
git clone https://github.com/dttdfr/DTT-UAB-The-Hack.git data/tarvia
copy .env.example .env
```

Abrid `.env` y rellenad estas tres líneas:
```
LLM_BASE_URL=https://dcc-llm-gw.uab.cat/uabthehack/v1
LLM_API_KEY=<la clave del equipo>
LLM_MODEL=ornith
```
El resto de variables pueden quedar vacías: el código usa valores por defecto correctos, como `SOC_API_URL` = `http://127.0.0.1:8000`.

**Si ya teníais el repo clonado**, en vez de clonarlo basta con:
```powershell
git checkout main
git pull
.venv\Scripts\python -m pip install -r requirements.txt
```

## 3. Arrancar (cada vez, dos terminales abiertas en la carpeta del proyecto)
**Terminal 1, la API simulada del SOC:**
```powershell
.venv\Scripts\python -m uvicorn mock_soc_api:app --app-dir data/tarvia/06_herramientas --host 127.0.0.1 --port 8000
```

**Terminal 2, la web:**
```powershell
.venv\Scripts\python -m src.web
```

El navegador se abre solo en **http://127.0.0.1:8080**. Dejad las dos terminales abiertas mientras uséis la web.

## 4. Preparar el modo demo (una vez por ordenador, unos 1,5 minutos)
Los resultados guardados no están en git (`data/` está ignorada), así que en un ordenador nuevo la cola sale sin triar. Con las dos terminales anteriores en marcha, abrid una tercera:
```powershell
.venv\Scripts\python -m scripts.preparar_demo --informe
```
Tría las 10 alertas de la cola y las 5 del phishing de SSO, y genera el informe N3. Después ya funciona el **Modo demo** aunque falle el servidor del DCC.

Antes de la defensa, borrad el registro de contención para empezar vacíos:
```powershell
Remove-Item data\tarvia\06_herramientas\containment_log.jsonl -ErrorAction SilentlyContinue
```

## 5. Comprobar que todo está bien (opcional)
```powershell
.venv\Scripts\python -m pytest -q
```
Deberían salir todos los tests en verde (177 el 7-nov).

## Problemas típicos
| Síntoma | Solución |
|---|---|
| Cada consulta tarda unos 2 s más | Usad `127.0.0.1` y no `localhost`. En Windows, `localhost` prueba primero IPv6 y la API solo escucha en IPv4. |
| `.venv\Scripts\activate` da error de permisos | No hace falta activarlo: los comandos de esta guía llaman directamente a `.venv\Scripts\python`. |
| «Address already in use» | Ya hay algo usando el puerto 8000 o el 8080 (quizá una terminal anterior). Cerradla, o arrancad la web en otro puerto: `$env:WEB_PORT=8081; .venv\Scripts\python -m src.web`. |
| La cabecera marca el SOC en rojo | La terminal 1 no está arrancada o se ha cerrado. |
| Un triaje tarda más de unos 30 s o da error | El servidor del DCC está saturado o caído. **La cabecera no lo avisa**: activad el **Modo demo**. |
| La cola sale sin triar | Falta el paso 4 (`scripts.preparar_demo`). |

Cómo está hecha la web y qué hace cada pantalla: [`docs/web.md`](web.md). Guion de la demo y plan B: [`docs/pitch.md`](pitch.md).
