"""python -m src.web  →  la interfaz en http://127.0.0.1:8080 (la API del SOC debe estar arrancada)."""

import os
import webbrowser

import uvicorn

PUERTO = int(os.getenv("WEB_PORT", "8080"))

if __name__ == "__main__":
    if os.getenv("WEB_ABRIR", "1") != "0":
        webbrowser.open(f"http://127.0.0.1:{PUERTO}")
    uvicorn.run("src.web.api:app", host="127.0.0.1", port=PUERTO)
