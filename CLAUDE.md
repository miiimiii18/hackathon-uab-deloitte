# CLAUDE.md

Contexto e instrucciones para Claude Code en este repositorio.

## Proyecto

- **Equipo:** TEMIPO.
- **Evento:** UAB The Hack, el hackathon de la Universitat Autònoma de Barcelona (2026).
- **Reto:** Deloitte, que combina ciberseguridad e inteligencia artificial. En ediciones anteriores incluía misiones de hacking y otras relacionadas con datos.
- **Quiénes somos:** estudiantes del grado de IA.
- **Prioridad:** el tiempo es limitado. Preferimos soluciones que funcionen y se puedan enseñar en una demo antes que código perfecto.

## Briefing del reto

> Pendiente: lo rellenaremos cuando tengamos el briefing oficial de Deloitte.

- **Enunciado:** ...
- **Misiones / entregables:** ...
- **Sistemas y datos autorizados:** ...
- **Criterios de evaluación:** ...
- **Plazos:** ...

## Repositorio

- GitHub: `miiimiii18/hackathon-uab-deloitte` (privado). Trabajamos varias personas a la vez.
- Lenguaje: Python 3.11, que es la versión del CI.

### Estructura

```
├── src/          # código principal (punto de entrada: src/main.py)
├── notebooks/    # exploración y prototipos
├── data/         # datos locales, ignorados por git (excepto data/README.md)
├── writeups/     # un .md por misión resuelta, a partir de writeups/_plantilla.md
├── docs/         # pitch (docs/pitch.md) y documentación
├── scripts/      # utilidades (setup.sh)
└── tests/        # tests con pytest
```

### Comandos habituales

```bash
python -m src.main     # ejecutar el proyecto
pytest -q              # tests
ruff check .           # linter
```

El CI (`.github/workflows/ci.yml`) ejecuta `ruff check .` y `pytest -q` en cada push a `main` y en cada Pull Request. Si alguno falla, el PR no está listo.

### Entorno en Windows

Trabajamos en Windows. `scripts/setup.sh` está escrito para Linux/macOS (`python3`, `source .venv/bin/activate`). En Windows, el equivalente es:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

## Flujo de trabajo con git

**Nunca hagas commits directamente en `main`.** `main` tiene que funcionar siempre, porque es lo que se presenta.

Para cada tarea:

1. Ponte en `main` y haz `git pull` para tenerlo actualizado.
2. Crea una rama nueva: `feat/nombre-tarea` o `fix/nombre-arreglo` (y `docs/...` para cambios que solo tocan documentación).
3. Haz commits pequeños en esa rama.
4. Al terminar, haz push de la rama y avisa para abrir el Pull Request en GitHub.

**Antes de cualquier commit o push:** explica qué se va a subir y espera a que lo confirmen.

### Mensajes de commit

Se usan prefijos, como en `CONTRIBUTING.md`:

```
feat: añade clasificador de logs
fix: corrige parser de CSV
docs: actualiza README
```

Las 2 últimas horas antes de la entrega `main` queda congelada: solo se aceptan arreglos y cosas de la demo.

## Seguridad y ética

- **Nunca** subas a git el archivo `.env`, claves de API, credenciales ni datos sensibles. Usa `.env.example` como modelo y añade ahí las variables nuevas, siempre sin valores reales.
- Los datasets van en `data/`, que git ignora. Anota de dónde sale cada uno en `data/README.md`.
- Las pruebas de seguridad se hacen **solo** sobre los sistemas y datos que la organización del reto haya autorizado. Si no está claro que algo está autorizado, pregunta antes.

## Documentar sobre la marcha

- Cada misión resuelta tiene su writeup en `writeups/NN-nombre-mision.md`, creado a partir de `writeups/_plantilla.md`.
- El guion del pitch está en `docs/pitch.md`.

## Cómo comunicarte con nosotros

- Responde en **español**.
- Explica brevemente lo que haces y por qué: estamos aprendiendo y queremos entender el código.
