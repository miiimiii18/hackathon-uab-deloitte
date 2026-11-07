# TEMIPO — UAB The Hack · Reto Deloitte (Ciber + IA)

> Una frase que explique qué hace vuestro proyecto y para quién.

## 👥 Equipo

| Nombre | Rol | GitHub |
|--------|-----|--------|
| Miriam Morales | ... | @... |
| ... | ... | @... |
| ... | ... | @... |

## 🎯 El reto

Resumen del reto de Deloitte con vuestras palabras (copiadlo del briefing el día del evento).

## 💡 Nuestra solución

- **Problema:** ...
- **Enfoque:** ...
- **Qué aporta la IA:** ...
- **Qué aporta la parte de ciberseguridad:** ...

## 🚀 Cómo ejecutarlo

Guía completa, paso a paso y con los problemas típicos: **[`docs/arrancar.md`](docs/arrancar.md)**.

Resumen (Windows, PowerShell):
```powershell
git clone https://github.com/miiimiii18/hackathon-uab-deloitte.git
cd hackathon-uab-deloitte
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
git clone https://github.com/dttdfr/DTT-UAB-The-Hack.git data/tarvia   # dataset de Deloitte
copy .env.example .env                                                   # pon LLM_API_KEY (NUNCA subas .env)

# Terminal 1: API simulada del SOC
.venv\Scripts\python -m uvicorn mock_soc_api:app --app-dir data/tarvia/06_herramientas --host 127.0.0.1 --port 8000
# Terminal 2: la web → http://127.0.0.1:8080
.venv\Scripts\python -m src.web
# Terminal 3 (una vez por ordenador): resultados guardados para el modo demo
.venv\Scripts\python -m scripts.preparar_demo --informe
```

## 🗂️ Estructura

```
├── src/          # código principal
├── notebooks/    # exploración y prototipos
├── data/         # datos locales (ignorados por git)
├── writeups/     # resolución de misiones / retos de hacking
├── docs/         # pitch, diagramas, notas
├── scripts/      # utilidades (setup, etc.)
└── tests/        # tests
```

## 📽️ Demo y presentación

- Vídeo / capturas: ...
- Slides: `docs/pitch.md`

## ⚖️ Ética y alcance

Todas las pruebas de seguridad se realizan **solo** sobre los sistemas y datos que la organización del reto ha autorizado.
No se suben credenciales, datos personales ni datos sensibles al repositorio.
