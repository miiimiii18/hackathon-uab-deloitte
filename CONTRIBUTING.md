# Cómo trabajamos (versión hackathon)

## Ramas
- `main` → siempre funciona. Es lo que se presenta.
- `feat/<lo-que-haces>` → una rama por tarea (ej. `feat/modelo-deteccion`, `feat/dashboard`).
- `fix/<que-arreglas>` → arreglos rápidos.

## Flujo
1. `git pull origin main`
2. `git checkout -b feat/mi-tarea`
3. Commits pequeños y frecuentes.
4. `git push -u origin feat/mi-tarea` y abrir Pull Request.
5. Otra persona del equipo le echa un vistazo rápido y se mergea.

## Mensajes de commit
```
feat: añade clasificador de logs
fix: corrige parser de CSV
docs: actualiza README
```

## Reglas de oro
- Nunca subas `.env`, claves de API ni datos sensibles.
- Si rompes `main`, avisa en el grupo enseguida.
- Las últimas 2 h antes de la entrega: congelamos `main`, solo arreglos y demo.
