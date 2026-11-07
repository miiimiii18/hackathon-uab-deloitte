import { api, ErrorConexion, triar } from "./api.js";
import { aviso } from "./util.js";

// Estado de la cola en el navegador. La decisión de cada alerta la toma el servidor; aquí solo
// se guarda qué alertas hay y en qué etapa van.
const CLAVE_COLA = "temipo.cola";
const CLAVE_PEGADAS = "temipo.pegadas";
const CLAVE_DEMO = "temipo.demo";

export const estado = {
  filas: new Map(), // id → { id, meta, etapa, resumen, error }
  grupos: new Map(), // id de alerta → grupo (alertas del mismo ataque con su ticket único)
  pegadas: {}, // alertas pegadas o subidas (no están en el dataset): id → alerta completa
  demo: false,
  servidor: null,
  triando: false,
  segundos: 0,
  total: 0,
};

const oyentes = new Set();
export const suscribir = (f) => { oyentes.add(f); return () => oyentes.delete(f); };
export const avisar = () => oyentes.forEach((f) => f());

const leer = (clave, defecto) => {
  const crudo = localStorage.getItem(clave);
  return crudo ? JSON.parse(crudo) : defecto;
};
const guardarCola = () => {
  localStorage.setItem(CLAVE_COLA, JSON.stringify([...estado.filas.keys()]));
  localStorage.setItem(CLAVE_PEGADAS, JSON.stringify(estado.pegadas));
};

function fila(id, meta) {
  return { id, meta: meta ?? null, etapa: "pendiente", resumen: null, error: null };
}

function aplicarResumen(f, resumen) {
  f.resumen = resumen;
  f.meta = resumen.meta ?? f.meta;
  f.error = resumen.error ?? null;
  f.etapa = f.error ? "error" : "listo";
}

// Qué alertas triadas forman parte del mismo ataque. Lo calcula el servidor; si falla, la cola sigue sin grupos.
export async function cargarGrupos() {
  const grupos = await api.grupos().catch(() => []);
  estado.grupos = new Map(grupos.flatMap((g) => g.alert_ids.map((id) => [id, g])));
  avisar();
}

export async function iniciar() {
  estado.demo = leer(CLAVE_DEMO, false);
  estado.pegadas = leer(CLAVE_PEGADAS, {});
  let ids = leer(CLAVE_COLA, null);
  let metas = {};
  if (!ids) {
    const inicial = await api.colaInicial();
    ids = inicial.map((a) => a.alert_id);
    metas = Object.fromEntries(inicial.map((a) => [a.alert_id, a]));
  }
  for (const id of ids) {
    const meta = metas[id] ?? (estado.pegadas[id] ? resumenPegada(estado.pegadas[id]) : await api.alerta(id).catch(() => null));
    estado.filas.set(id, fila(id, meta));
  }
  for (const r of await api.resultados()) {
    const f = estado.filas.get(r.alert_id);
    if (f) aplicarResumen(f, r);
  }
  guardarCola();
  avisar();
  await cargarGrupos();
}

const resumenPegada = (a) => ({ alert_id: a.alert_id, rule_id: a.rule_id, rule_name: a.rule_name ?? a.rule_id, severity: a.severity, source_product: a.source_product, created_at: a.created_at });

export function ponerDemo(valor) {
  estado.demo = valor;
  localStorage.setItem(CLAVE_DEMO, JSON.stringify(valor));
  avisar();
}

export async function añadirAlertas({ ids = [], objetos = [] }) {
  for (const a of objetos) {
    estado.pegadas[a.alert_id] = a;
    estado.filas.set(a.alert_id, fila(a.alert_id, resumenPegada(a)));
  }
  for (const id of ids) {
    if (!estado.filas.has(id)) estado.filas.set(id, fila(id, await api.alerta(id).catch(() => null)));
  }
  guardarCola();
  avisar();
  return [...ids, ...objetos.map((a) => a.alert_id)];
}

export async function restablecerCola() {
  localStorage.removeItem(CLAVE_COLA);
  localStorage.removeItem(CLAVE_PEGADAS);
  estado.filas.clear();
  estado.pegadas = {};
  await iniciar();
}

export async function triarFilas(ids, paralelo = 5) {
  if (estado.triando || !ids.length) return;
  estado.triando = true;
  estado.total = ids.length;
  const inicio = performance.now();
  const reloj = setInterval(() => { estado.segundos = (performance.now() - inicio) / 1000; avisar(); }, 250);
  for (const id of ids) Object.assign(estado.filas.get(id), { etapa: "pendiente", resumen: null, error: null });
  avisar();
  const referencias = ids.map((id) => estado.pegadas[id] ?? id);
  const desde = Date.now() - 2000; // margen por si los relojes no van clavados
  try {
    await triar(referencias, { paralelo, demo: estado.demo }, (ev) => {
      const f = estado.filas.get(ids[ev.posicion]);
      if (!f) return;
      if (ev.tipo === "etapa") f.etapa = ev.etapa;
      if (ev.tipo === "resultado") aplicarResumen(f, ev.resumen);
      avisar();
    });
  } catch (e) {
    aviso(`No se pudo seguir el triaje: ${e.message}`);
    if (e instanceof ErrorConexion && !estado.demo) await recuperar(ids, desde);
    for (const id of ids) {
      const f = estado.filas.get(id);
      if (f.etapa !== "listo" && f.etapa !== "error") Object.assign(f, { etapa: "error", error: e.message });
    }
  } finally {
    clearInterval(reloj);
    estado.segundos = (performance.now() - inicio) / 1000;
    estado.triando = false;
    avisar();
    await cargarGrupos();
  }
}

// Si se corta la conexión con el flujo, el servidor sigue triando y guardando: se consultan sus
// resultados hasta que estén todas (o se agote la espera). Solo valen los posteriores al inicio.
async function recuperar(ids, desde, esperaMaxima = 120000) {
  const limite = Date.now() + esperaMaxima;
  let fallos = 0;
  while (Date.now() < limite && fallos < 3) { // con el servidor caído no tiene sentido seguir esperando
    const resumenes = await api.resultados().catch(() => null);
    fallos = resumenes ? 0 : fallos + 1;
    if (resumenes) {
      for (const r of resumenes) {
        const f = estado.filas.get(r.alert_id);
        if (f && ids.includes(r.alert_id) && f.etapa !== "listo" && r.triado_en && Date.parse(r.triado_en) >= desde) aplicarResumen(f, r);
      }
      avisar();
      if (ids.every((id) => ["listo", "error"].includes(estado.filas.get(id).etapa))) return;
    }
    await new Promise((resolver) => setTimeout(resolver, 3000));
  }
}

export async function refrescarResultado(id) {
  const f = estado.filas.get(id);
  const lista = await api.resultados();
  const r = lista.find((x) => x.alert_id === id);
  if (f && r) aplicarResumen(f, r);
  avisar();
}
