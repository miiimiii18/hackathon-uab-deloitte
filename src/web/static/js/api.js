// Error de red (servidor caído, conexión cortada): distinto de un error que el servidor explica.
export class ErrorConexion extends Error {
  constructor(detalle = "") {
    super(`No hay conexión con el servidor de la web${detalle ? ` (${detalle})` : ""}. ¿Sigue arrancado «python -m src.web»?`);
  }
}

const conRed = async (promesa) => {
  try {
    return await promesa;
  } catch (e) {
    if (e instanceof TypeError) throw new ErrorConexion(e.message);
    throw e;
  }
};

async function explicar(r) {
  const cuerpo = await r.json().catch(() => null);
  const detalle = cuerpo?.detail;
  return typeof detalle === "string" ? detalle : JSON.stringify(detalle ?? r.statusText);
}

async function pedir(ruta, opciones) {
  const r = await conRed(fetch(ruta, opciones));
  if (!r.ok) throw new Error(await explicar(r));
  return r.json();
}

const enviar = (ruta, cuerpo) =>
  pedir(ruta, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cuerpo) });

export const api = {
  estado: () => pedir("/api/estado"),
  colaInicial: () => pedir("/api/cola-inicial"),
  alerta: (id) => pedir(`/api/alertas/${encodeURIComponent(id)}`),
  buscar: (q) => pedir(`/api/alertas?q=${encodeURIComponent(q)}&limite=60`),
  resultados: () => pedir("/api/resultados"),
  resultado: (id) => pedir(`/api/resultados/${encodeURIComponent(id)}`),
  ejecutar: (id, indice, cuerpo) => enviar(`/api/resultados/${encodeURIComponent(id)}/acciones/${indice}/ejecutar`, cuerpo),
  decidir: (id, cuerpo) => enviar(`/api/resultados/${encodeURIComponent(id)}/decisiones`, cuerpo),
};

// Triaje en directo: el servidor responde con eventos SSE (etapa por alerta y resultado al terminar).
// Si la conexión se corta antes del evento «fin» se lanza ErrorConexion: el servidor sigue triando
// y guardando, así que quien llama puede recuperar los resultados.
export async function triar(alertas, { paralelo, demo }, alEvento) {
  const r = await conRed(fetch("/api/triaje", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alertas, paralelo, demo }),
  }));
  if (!r.ok) throw new Error(await explicar(r));
  const lector = r.body.getReader();
  const decodificador = new TextDecoder();
  let pendiente = "";
  let terminado = false;
  for (;;) {
    const { done, value } = await conRed(lector.read());
    if (done) break;
    pendiente += decodificador.decode(value, { stream: true });
    const bloques = pendiente.split("\n\n");
    pendiente = bloques.pop();
    for (const bloque of bloques) {
      if (!bloque.startsWith("data: ")) continue; // los comentarios («: pulso») solo mantienen viva la conexión
      const evento = JSON.parse(bloque.slice(6));
      if (evento.tipo === "error") throw new Error(evento.mensaje);
      if (evento.tipo === "fin") terminado = true;
      alEvento(evento);
    }
  }
  if (!terminado) throw new ErrorConexion("la conexión se cortó antes de terminar");
}
