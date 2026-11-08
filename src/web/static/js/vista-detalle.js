import { api } from "./api.js";
import { h, icono, svg } from "./dom.js";
import { estado, refrescarResultado, suscribir, triarFilas } from "./estado.js";
import { aviso, cortar, DECISION, descargar, gravedad, hora, legible, SELLO, SEVERIDADES, siNo, veredicto, VEREDICTO } from "./util.js";

// El detalle como un expediente: arriba la conclusión y quién decide qué; a la izquierda el porqué
// (cronología, implicados, dudas, investigación); a la derecha qué consultó, cómo se calcula la
// gravedad y la contención que firma una persona. Todo sale del resultado del servidor.

const esObjeto = (v) => v && typeof v === "object" && !Array.isArray(v);
const kv = (clave, valor) => h("div", { class: "kv" }, h("span", {}, clave), h("span", {}, valor));
const mono = (t) => h("span", { class: "m", style: { fontSize: "12.5px" } }, t);
const chip = (texto, clase = "") => h("span", { class: `chip ${clase}` }, texto);
const crudo = (objeto, texto = "Ver datos en bruto") => h("details", {}, h("summary", {}, texto), h("pre", { class: "json" }, JSON.stringify(objeto, null, 2)));
const nivel = (n) => h("span", { class: "nivel" }, n);
const horaCorta = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString("es-ES", { timeZone: "Europe/Madrid", hour: "2-digit", minute: "2-digit", second: "2-digit" });
};
const diaCorto = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString("es-ES", { timeZone: "Europe/Madrid", day: "numeric", month: "short" });
};

function bloque(titulo, niveles, lado, ...contenido) {
  return h("section", { class: "bloque", "aria-label": titulo },
    h("h2", {}, titulo, ...niveles.map(nivel), lado ? h("span", { class: "lado" }, lado) : null), ...contenido);
}

function texto(attrs, contenido) {
  const t = svg("text", attrs);
  t.textContent = contenido;
  return t;
}

// --- Eventos: los que cita la IA, con su hora, marcando los que no venían en la alerta -----------

function eventosConHora(r) {
  const ev = r.evidencia || {};
  const porId = new Map();
  for (const e of ev.eventos_citados_en_la_alerta || []) if (e.event_id) porId.set(e.event_id, e);
  for (const l of ev.contexto_logs || []) for (const e of l.muestra || []) if (e.event_id && !porId.has(e.event_id)) porId.set(e.event_id, { ...e, fuente: l.fuente });
  return porId;
}

const relacionados = (r) => new Set(r.alerta?.related_events || []);

// --- Qué ha consultado -----------------------------------------------------------------------

const TIPO_CONSULTA = [[/^\/alerts/, "#1B1A17", "alerta"], [/^\/(assets|users)/, "#7C93C3", "inventario"], [/^\/(intel|sandbox)/, "#C2381D", "inteligencia · sandbox"],
  [/^\/changes/, "#A8701A", "cambios"], [/^\/logs/, "#9C9483", "registros ±24 h"]];
const colorConsulta = (c) => (TIPO_CONSULTA.find(([re]) => re.test(c)) ?? [null, "#B4B2A9"])[1];

function parametros(p) {
  return Object.entries(p || {}).filter(([k]) => !["limit", "desde", "hasta"].includes(k)).map(([k, v]) => `${k}=${v}`).join(" ");
}

function consultas(r) {
  const traza = r.traza || [];
  const total = Math.max(1, traza.reduce((s, t) => s + (t.ms || 0), 0));
  let acumulado = 0;
  const filas = traza.map((t) => {
    const izquierda = (acumulado / total) * 100;
    acumulado += t.ms || 0;
    const resultado = t.desconocido ? "404 · desconocido" : t.cache ? "caché" : t.estado && t.estado !== 200 ? `error ${t.estado}` : `${t.resultados} res.`;
    return h("div", { class: "f", title: `${t.consulta} ${parametros(t.parametros)} · ${t.ms} ms` },
      h("span", {}, t.consulta, " ", h("span", { style: { color: "var(--mu)" } }, cortar(parametros(t.parametros), 40))),
      h("span", { class: "b" }, h("span", { style: { left: `${izquierda}%`, width: `${Math.max(((t.ms || 0) / total) * 100, 0.6)}%`, background: colorConsulta(t.consulta) } })),
      h("span", { style: { textAlign: "right", color: t.desconocido ? "var(--med)" : t.resultados ? "var(--tx)" : "var(--tenue)" } }, resultado));
  });
  return bloque("Qué ha consultado", ["N1"], `${traza.length} consultas · ${(total / 1000).toFixed(1)} s`,
    h("div", { class: "tope" }, h("div", { class: "consultas" }, ...filas)),
    h("div", { class: "leyenda" }, ...TIPO_CONSULTA.map(([, color, nombre]) => h("span", {}, h("i", { style: { background: color } }), nombre))));
}

// --- Por qué (la IA, con citas) ----------------------------------------------------------------

const SENALES = {
  ejecucion_o_acceso_confirmado: "Ejecución o acceso confirmado",
  identidad_vip_o_privilegiada: "Identidad VIP o privilegiada",
  datos_personales_o_pagos: "Datos personales o pagos",
  bloqueado_sin_actividad_posterior: "Bloqueado sin actividad posterior",
  actividad_autorizada: "Actividad autorizada",
};

function porQue(r) {
  const ia = r.llm?.analisis;
  if (!ia) return bloque("Por qué", ["N1"], null, h("p", { class: "nota" }, "Este resultado no tiene análisis de la IA."));
  const rel = relacionados(r);
  const porId = eventosConHora(r);
  const items = (ia.evidence || []).map((e) => {
    // Solo es «fuera de la alerta» un evento real de los registros que la alerta no traía (no la alerta ni un cambio).
    const fuera = e.event_id && rel.size && porId.has(e.event_id) && !rel.has(e.event_id);
    return h("li", { style: { margin: "6px 0" } },
      h("span", { class: "ia-voz", style: { fontSize: "15px" } }, e.finding), " ",
      e.event_id ? h("span", { class: `cita ${fuera ? "fuera" : ""}`, title: fuera ? "Evento que NO venía en la alerta: lo encontró el triaje" : "Evento citado" }, e.event_id) : null,
      e.source ? h("span", { class: "m", style: { fontSize: "11px", color: "var(--mu)" } }, ` ${e.source}`) : null,
      fuera ? h("span", { class: "m", style: { fontSize: "11px", color: "var(--med)" } }, " · fuera de la alerta") : null);
  });
  return bloque("Por qué lo dice la IA", ["N1"], `${r.llm.modelo} · ${Math.round(r.llm.segundos ?? 0)} s`,
    items.length ? h("ul", { style: { margin: 0, paddingLeft: "18px" } }, ...items) : h("p", { class: "nota" }, "La IA no citó eventos."),
    h("div", { class: "senales" }, ...Object.entries(SENALES).map(([k, t]) => h("span", { class: `sen ${ia.senales?.[k] ? "si" : ""}` }, h("b"), t))),
    (ia.mitre || []).length ? h("div", { class: "mitre" }, ...ia.mitre.map((m) => chip(m))) : null);
}

// --- La cadena, paso a paso (cronología con los eventos citados) --------------------------------

function cronologia(r) {
  const porId = eventosConHora(r);
  const rel = relacionados(r);
  const ia = r.llm?.analisis;
  const pasos = (ia?.evidence || [])
    .map((e) => ({ ...e, evento: porId.get(e.event_id) }))
    .filter((e) => e.evento?.timestamp)
    .filter((e, i, l) => l.findIndex((x) => x.event_id === e.event_id) === i)
    .sort((a, b) => Date.parse(a.evento.timestamp) - Date.parse(b.evento.timestamp))
    .slice(0, 7);
  if (pasos.length < 2) return null;
  const ancho = 720, n = pasos.length, paso = (ancho - 120) / (n - 1);
  const mismoDia = new Set(pasos.map((p) => diaCorto(p.evento.timestamp))).size === 1;
  const hijos = [svg("line", { x1: 20, y1: 70, x2: ancho - 20, y2: 70, stroke: "#1B1A17" })];
  pasos.forEach((p, i) => {
    const x = 60 + i * paso, arriba = i % 2 === 0;
    const fuera = rel.size && !rel.has(p.event_id);
    // Los extremos se alinean hacia dentro para que el texto no se salga del dibujo.
    const ancla = i === 0 ? "start" : i === n - 1 ? "end" : "middle";
    const tx = i === 0 ? x - 8 : i === n - 1 ? x + 8 : x;
    hijos.push(
      svg("line", { x1: x, y1: arriba ? 64 : 76, x2: x, y2: arriba ? 40 : 100, stroke: "#A39D8F" }),
      svg("circle", { cx: x, cy: 70, r: 5.5, fill: fuera ? "#F4E8CF" : i === n - 1 ? "#C2381D" : "#FBF9F4", stroke: fuera ? "#A8701A" : "#1B1A17", "stroke-width": 1.5 }),
      texto({ x: tx, y: arriba ? 14 : 116, "text-anchor": ancla, "font-weight": 600 }, `${mismoDia ? "" : `${diaCorto(p.evento.timestamp)} `}${horaCorta(p.evento.timestamp)}`),
      texto({ x: tx, y: arriba ? 28 : 130, "text-anchor": ancla, class: "t-s" }, cortar(p.finding, n > 5 ? 24 : 32)),
      texto({ x: tx, y: arriba ? 40 : 142, "text-anchor": ancla, class: "t-g" }, `${p.event_id}${fuera ? " · fuera de la alerta" : ""}`));
  });
  const grafico = svg("svg", { class: "grafico", viewBox: `0 0 ${ancho} 150`, role: "img", "aria-label": "Cronología de los eventos citados" }, ...hijos);
  return bloque("La cadena, paso a paso", ["N3"], "hora de Madrid", grafico);
}

// --- Quién y qué está implicado (grafo de entidades) ---------------------------------------------

const ESTADO_IOC = { malicious: ["maliciosa", "#C2381D", "#F6E1DA"], suspicious: ["sospechosa", "#A8701A", "#F4E8CF"], unknown: ["desconocida", "#A8701A", "#F4E8CF"], clean: ["limpia", "#4A7552", "#E2EBDF"] };

function implicados(r) {
  const ent = r.alerta?.entities || {};
  const ev = r.evidencia || {};
  const intel = new Map((ev.inteligencia || []).map((i) => [String(i.indicador).toLowerCase(), i]));
  const personas = (ent.users || []).slice(0, 3).map((u) => {
    const upn = u.upn ?? u;
    const d = ev.usuarios?.[upn];
    return { t: u.display_name ?? upn, s: esObjeto(d) ? cortar([d.department, siNo(d.vip) === "Sí" ? "VIP" : null, siNo(d.privileged) === "Sí" ? "privilegiada" : null].filter(Boolean).join(" · "), 26) : "fuera del directorio", tipo: esObjeto(d) ? "n" : "u" };
  });
  const equipos = (ent.hosts || []).slice(0, 3).map((x) => {
    const nombre = x.hostname ?? x;
    const a = ev.activos?.[nombre];
    return { t: nombre, s: esObjeto(a) ? cortar(`${a.type ?? "equipo"} · crit. ${String(a.criticality ?? "?").toLowerCase()}`, 26) : "no está en la CMDB", tipo: esObjeto(a) ? "n" : "u" };
  });
  const ioc = (valor, nombre) => {
    const i = intel.get(String(valor).toLowerCase());
    const [estadoT] = ESTADO_IOC[i?.estado] ?? ["sin consultar"];
    const familia = i?.tip?.malware_family;
    return { t: cortar(nombre ?? valor, 22), s: familia ? `${estadoT} · ${familia}` : estadoT, tipo: i?.estado ?? "x" };
  };
  const indicadores = [
    ...(ent.domains || []).map((d) => ioc(d)),
    ...(ent.ips || []).map((d) => ioc(d.ip ?? d)),
    ...(ent.files || []).map((f) => ioc(f.sha256 ?? f.name, f.name)),
    ...(ent.urls || []).map((u) => ioc(u)),
  ];
  const visibles = indicadores.slice(0, 5);
  if (!personas.length && !equipos.length && !visibles.length) return null;

  const columnas = [personas, equipos, visibles].filter((c) => c.length);
  const filasMax = Math.max(...columnas.map((c) => c.length));
  const alto = Math.max(90, filasMax * 52 + 20), ancho = 720;
  const xs = columnas.length === 3 ? [100, 340, 600] : columnas.length === 2 ? [150, 520] : [360];
  const pos = columnas.map((c, ci) => c.map((_, i) => [xs[ci], (alto / (c.length + 1)) * (i + 1)]));
  const hijos = [];
  for (let ci = 0; ci < columnas.length - 1; ci++) {
    for (const [x1, y1] of pos[ci]) for (const [x2, y2] of pos[ci + 1]) hijos.push(svg("line", { x1: x1 + 78, y1, x2: x2 - 78, y2, stroke: "#C9C2B2" }));
  }
  columnas.forEach((c, ci) => c.forEach((nodo, i) => {
    const [x, y] = pos[ci][i];
    const [, borde, fondo] = ESTADO_IOC[nodo.tipo] ?? [null, nodo.tipo === "u" ? "#A8701A" : "#1B1A17", nodo.tipo === "u" ? "#F4E8CF" : "#FBF9F4"];
    const dudoso = nodo.tipo === "unknown" || nodo.tipo === "u" || nodo.tipo === "x";
    hijos.push(svg("rect", { x: x - 78, y: y - 20, width: 156, height: 40, rx: 3, fill: fondo, stroke: borde, ...(dudoso ? { "stroke-dasharray": "4 3" } : {}) }),
      texto({ x, y: y - 3, "text-anchor": "middle", "font-weight": 600 }, nodo.t),
      texto({ x, y: y + 12, "text-anchor": "middle", class: "t-g" }, nodo.s));
  }));
  const grafico = svg("svg", { class: "grafico", viewBox: `0 0 ${ancho} ${alto}`, role: "img", "aria-label": "Personas, equipos e indicadores de la alerta" }, ...hijos);
  return bloque("Quién y qué está implicado", ["N1"], indicadores.length > 5 ? `+${indicadores.length - 5} indicadores más` : null, grafico);
}

// --- Dudas, evidencia completa y alerta original -------------------------------------------------

function dudas(r) {
  const q = r.llm?.analisis?.open_questions || [];
  if (!q.length) return null;
  return bloque("Lo que la IA no sabe todavía", [], null, h("ul", { class: "dudas" }, ...q.map((x) => h("li", {}, x))));
}

function bloqueActivos(ev) {
  const entradas = Object.entries(ev.activos || {});
  return h("div", {}, h("h3", {}, "Equipos"),
    ...(entradas.length ? entradas.map(([host, a]) => esObjeto(a)
      ? h("div", {}, kv("Equipo", mono(host)), kv("Tipo", a.type ?? "—"), kv("Criticidad", h("b", {}, a.criticality ?? "—")), kv("Zona", a.zone ?? "—"), kv("Servicio", a.business_service ?? "—"))
      : h("div", {}, kv("Equipo", mono(host)), kv("CMDB", h("span", { class: "tg unk" }, "desconocido")))) : [h("p", { class: "nota" }, "La alerta no apunta a ningún equipo")]));
}

function bloqueUsuarios(ev) {
  const entradas = Object.entries(ev.usuarios || {});
  return h("div", {}, h("h3", {}, "Personas"),
    ...(entradas.length ? entradas.map(([upn, u]) => esObjeto(u)
      ? h("div", {}, kv("Usuario", mono(u.username ?? upn)), kv("Puesto", cortar(`${u.department ?? ""} · ${u.title ?? ""}`, 40)), kv("VIP", siNo(u.vip)), kv("Privilegiada", siNo(u.privileged)))
      : h("div", {}, kv("Usuario", mono(upn)), kv("Directorio", h("span", { class: "tg unk" }, "desconocido")))) : [h("p", { class: "nota" }, "La alerta no apunta a ningún usuario")]));
}

function bloqueInteligencia(ev) {
  const lista = ev.inteligencia || [];
  return h("div", {}, h("h3", {}, "Inteligencia"),
    ...(lista.length ? lista.map((i) => {
      const geo = i.geo ? [i.geo.country, i.geo.city].filter(Boolean).join(", ") : "";
      return h("div", {}, kv(mono(cortar(i.indicador, 30)), h("span", { class: `tg ${{ malicious: "bad", suspicious: "unk", unknown: "unk", clean: "clean" }[i.estado] ?? ""}` }, ESTADO_IOC[i.estado]?.[0] ?? i.estado)),
        geo ? kv("Origen", cortar(`${geo} · ${i.geo.as_org ?? ""}`, 46)) : null);
    }) : [h("p", { class: "nota" }, "Sin indicadores que enriquecer")]),
    null);
}

function bloqueContexto(ev) {
  const sandbox = Object.entries(ev.sandbox || {});
  const cambios = ev.cambios_aprobados || [];
  return h("div", {}, h("h3", {}, "Sandbox y cambios"),
    ...sandbox.map(([sha, s]) => (esObjeto(s)
      ? kv(`Sandbox ${sha.slice(0, 8)}…`, h("b", {}, `${s.malware_family ?? s.verdict ?? "informe"}${s.score != null ? ` · ${s.score}` : ""}`))
      : kv(`Sandbox ${sha.slice(0, 8)}…`, h("span", { class: "tg unk" }, "sin informe")))),
    kv("Cambios aprobados", cambios.length ? h("b", {}, cambios.map((c) => c.id ?? c.change_id ?? "?").join(", ")) : "Ninguno"),
    kv("Eventos citados en la alerta", `${(ev.eventos_citados_en_la_alerta || []).length}`));
}

function bloqueLogs(ev) {
  const logs = ev.contexto_logs || [];
  if (!logs.length) return null;
  return h("div", { style: { gridColumn: "1 / -1" } }, h("h3", {}, "Registros consultados (±24 h)"),
    ...logs.map((l) => h("div", {},
      kv(h("span", {}, mono(l.fuente), " ", h("span", { style: { color: "var(--mu)" } }, cortar(l.busqueda, 40))), h("b", {}, `${l.total}${l.truncado ? "+" : ""} evento${l.total === 1 ? "" : "s"}`)),
      l.muestra?.length ? crudo(l.muestra, "Ver eventos") : null)));
}

function evidenciaCompleta(r) {
  const ev = r.evidencia || {};
  return h("details", { class: "pliego" }, h("summary", {}, "En qué se basa: toda la evidencia reunida"),
    h("div", { class: "base", style: { marginTop: "10px" } }, bloqueActivos(ev), bloqueUsuarios(ev), bloqueInteligencia(ev), bloqueContexto(ev), bloqueLogs(ev)),
    (ev.notas || []).length ? h("p", { class: "nota", style: { marginTop: "8px" } }, ev.notas.join(" ")) : null);
}

function alertaOriginal(id, r) {
  const cuerpo = h("div", {}, h("p", { class: "nota" }, "Cargando…"));
  const pintar = (a) => cuerpo.replaceChildren(h("pre", { class: "json" }, JSON.stringify(a, null, 2)));
  const caja = h("details", { class: "pliego" }, h("summary", {}, "Alerta original, tal como llegó"), cuerpo);
  caja.addEventListener("toggle", () => {
    if (!caja.open || cuerpo.dataset.cargada) return;
    cuerpo.dataset.cargada = "1";
    if (r.alerta) pintar(r.alerta);
    else api.original(id).then(pintar).catch((e) => cuerpo.replaceChildren(h("p", { class: "nota" }, `No se pudo cargar la alerta: ${e.message}`)));
  });
  return caja;
}

// --- Cómo se calcula la gravedad (lo decide el código) -------------------------------------------

function gravedadBloque(r) {
  const p = r.politica;
  if (!p) return bloque("Cómo se calcula la gravedad", ["N2"], null, h("p", { class: "nota" }, "Este resultado solo tiene evidencia."));
  const m = estado.servidor?.matriz;
  const corregido = p.veredicto_llm && p.veredicto_llm !== p.veredicto;
  let tabla = null;
  if (m) {
    const col = m.criticidades.indexOf(p.criticidad);
    tabla = h("div", { class: "matriz", role: "table", "aria-label": "Matriz de severidad de la política" },
      h("div", { class: "h", style: { textAlign: "right" } }, "regla ↓ activo →"), ...m.criticidades.map((c) => h("div", { class: "h" }, c.toLowerCase())),
      ...SEVERIDADES.flatMap((fila) => [h("div", { class: "h", style: { textAlign: "right" } }, gravedad(fila)),
        ...(m.filas[fila] || []).map((v, i) => h("div", { class: `${fila === p.severidad_regla ? "fila-on" : ""} ${fila === p.severidad_regla && i === col ? "on" : ""}` }, gravedad(v)))]));
  }
  const aj = Number(p.ajuste) || 0;
  return bloque("Cómo se calcula la gravedad", ["N2"], null,
    tabla,
    h("p", { class: "m", style: { margin: 0, fontSize: "12px", lineHeight: 1.7 } },
      "regla ", h("b", {}, gravedad(p.severidad_regla)), " × activo ", h("b", {}, String(p.criticidad).toLowerCase()), ` = ${gravedad(p.severidad_base)}`,
      aj ? ` ${aj > 0 ? "+" : "−"}${Math.abs(aj)} (${legible((p.motivos_ajuste || []).join(", ") || "ajuste")})` : "", " → ",
      h("span", { class: `sv ${p.severidad_final}` }, gravedad(p.severidad_final))),
    p.autorizacion ? h("div", { class: "ok-caja" }, `Autorización verificada: ${p.autorizacion}`) : null,
    corregido ? h("div", { class: "aviso-caja" }, `La IA dijo «${veredicto(p.veredicto_llm)}»; el código lo deja en «${veredicto(p.veredicto)}».`) : null,
    ...(p.avisos || []).map((a) => h("p", { class: "nota" }, `⚑ ${legible(a)}`)),
    (p.motivos_escalado || []).length ? kv("Escala porque", legible(p.motivos_escalado.join(" · "))) : null,
    p.sla ? kv("Plazo", [p.sla.tiempo_triaje, p.sla.escalado].filter(Boolean).join(" · ")) : null,
    p.sla?.notificar && p.sla.notificar !== "—" ? kv("Avisar a", p.sla.notificar) : null);
}

// --- Alertas del mismo ataque ----------------------------------------------------------------------

function grupoAtaque(id) {
  const g = estado.grupos.get(id);
  if (!g) return null;
  const t = g.ticket;
  return bloque("Mismo ataque", ["N2"], `${g.alert_ids.length} alertas · ${gravedad(g.severidad)}`,
    h("p", { class: "nota" }, legible(t.escalation.reason)),
    h("div", {}, ...g.alert_ids.map((a) => h("a", { class: "m", href: `#/alerta/${encodeURIComponent(a)}`, style: { display: "block", fontSize: "12.5px", padding: "2px 0" } }, a === id ? `${a} · esta` : a))),
    kv("Las une", cortar(g.entidades.join(" · "), 90)),
    kv("Ticket único", mono(t.ticket_id)),
    h("div", {}, h("button", { class: "btn sm", type: "button", onClick: () => descargar(`${t.ticket_id}.json`, t) }, "Ticket único (JSON)")));
}

// --- Informe de investigación (nivel 3) -------------------------------------------------------------

function lista(items) {
  return items?.length ? h("ul", { class: "lista" }, ...items.map((t) => h("li", {}, t))) : h("p", { class: "nota" }, "Nada que indicar.");
}

function seccion(titulo, ...contenido) {
  return h("div", { class: "seccion" }, h("h3", {}, titulo), ...contenido);
}

function verInforme(registro) {
  const i = registro.informe;
  const cumple = (registro.informe_errores || []).length === 0;
  return h("div", { style: { display: "flex", flexDirection: "column", gap: "14px" } },
    h("div", { class: "meta" }, mono(i.incident_id), chip(`${i.alert_ids.length} alerta${i.alert_ids.length === 1 ? "" : "s"}`),
      chip(`confianza ${Number(i.confidence).toFixed(2)}`, "c-ia"), chip(cumple ? "Cumple el esquema de Deloitte" : "Informe con errores de esquema", cumple ? "c-co" : "c-med")),
    seccion("Paciente cero", h("p", { style: { margin: 0 } }, i.patient_zero)),
    seccion("Acceso inicial", h("p", { class: "ia-voz", style: { margin: 0 } }, i.initial_access)),
    seccion("Línea de tiempo", h("div", { class: "scroll" }, h("div", { class: "tope" }, ...i.timeline.map((f) =>
      h("div", { class: "lt" }, h("span", { class: "m" }, hora(f.timestamp)), h("span", { class: "m" }, f.event_id), h("span", {}, f.description), h("span", { class: "m" }, f.mitre || "")))))),
    seccion("Alcance", kv("Usuarios", cortar((i.scope.users || []).join(", ") || "—", 90)), kv("Equipos", cortar((i.scope.hosts || []).join(", ") || "—", 90)),
      h("p", { class: "nota" }, i.scope.data), h("p", { class: "nota" }, i.scope.business_impact)),
    seccion("Causa raíz", h("p", { class: "ia-voz", style: { margin: 0 } }, i.root_cause)),
    seccion("Relación con otros incidentes (la calcula el código)", (i.related_incidents || []).length
      ? lista(i.related_incidents)
      : h("p", { class: "nota" }, "Ningún otro incidente escalado comparte entidades ni aparece en sus logs.")),
    seccion("Plan de contención (lo aprueba una persona)", ...(i.containment_plan.length ? i.containment_plan.map((p) => kv(h("span", { class: "m" }, p.action), h("span", {}, `${cortar(p.target, 60)} · ${p.approver}`))) : [h("p", { class: "nota" }, "Sin acciones.")])),
    seccion("Erradicación y recuperación", lista(i.eradication_and_recovery)),
    seccion("A quién avisar", lista(i.notifications)),
    seccion("Huecos de detección", lista(i.detection_gaps)),
    seccion("Preguntas abiertas", lista(i.open_questions)),
    h("div", {}, h("button", { class: "btn sm", type: "button", onClick: () => descargar(`${i.incident_id}.json`, i) }, "Informe (JSON)")));
}

function panelInforme(id, r) {
  if (r.politica?.decision !== "escalar") return null;
  const cuerpo = h("div", {}, h("p", { class: "nota" }, "Cargando…"));
  const mostrarBoton = (mensaje = "") => {
    const boton = h("button", { class: "btn go", type: "button", onClick: async () => {
      boton.disabled = true;
      boton.textContent = "Investigando…";
      try {
        cuerpo.replaceChildren(verInforme(await api.investigar(id)));
      } catch (e) {
        aviso(e.message);
        mostrarBoton(e.message);
      }
    } }, "Generar informe de investigación");
    cuerpo.replaceChildren(...[ // replaceChildren no ignora los null: se filtran
      mensaje ? h("div", { class: "err-caja" }, mensaje) : null, h("div", {}, boton)].filter(Boolean));
  };
  api.informe(id).then((g) => (g ? cuerpo.replaceChildren(verInforme(g)) : mostrarBoton()));
  return bloque("Informe de investigación", ["N3"], null, cuerpo);
}

// --- La persona decide -------------------------------------------------------------------------

function botonMantener(textoBoton, alCompletar, deshabilitado) {
  const relleno = h("i");
  const boton = h("button", { class: "mantener", type: "button", disabled: deshabilitado }, relleno, h("span", {}, textoBoton));
  let reloj = null;
  const empezar = () => {
    if (boton.disabled || reloj) return;
    relleno.style.transition = "width 1.1s linear";
    relleno.style.width = "100%";
    reloj = setTimeout(() => { reloj = null; relleno.style.transition = "none"; relleno.style.width = "0"; alCompletar(); }, 1100);
  };
  const soltar = () => {
    if (!reloj) return;
    clearTimeout(reloj);
    reloj = null;
    relleno.style.transition = "width .25s";
    relleno.style.width = "0";
  };
  boton.addEventListener("pointerdown", empezar);
  ["pointerup", "pointerleave", "pointercancel", "blur"].forEach((e) => boton.addEventListener(e, soltar));
  boton.addEventListener("keydown", (e) => { if ((e.key === " " || e.key === "Enter") && !e.repeat) { e.preventDefault(); empezar(); } });
  boton.addEventListener("keyup", (e) => { if (e.key === " " || e.key === "Enter") soltar(); });
  return boton;
}

const ejecutada = (t, a) => (t.executed_actions || []).find((e) => e.action === a.action && String(a.target).includes(e.target));

function tarjetaAccion(r, a, indice, recargar) {
  const t = r.ticket;
  const hecha = ejecutada(t, a);
  const rechazada = (r.humano || []).some((d) => d.tipo === "rechazar_accion" && d.indice === indice);
  const quien = !a.permitida ? "prohibida · OT" : hecha ? "ejecutada" : rechazada ? "rechazada" : a.requires_approval ? `aprueba ${a.aprobador}` : "N1 puede";
  const tarjeta = h("div", { class: `acto ${!a.permitida ? "prohibida" : hecha ? "hecha" : ""}` },
    h("div", { class: "cab" },
      h("span", { class: "caja", "aria-hidden": "true" }, hecha ? icono("check", 12, 3) : null),
      h("div", { style: { minWidth: 0 } }, h("b", { class: "m", style: { fontSize: "13px" } }, a.action), " ",
        h("span", { style: { overflowWrap: "anywhere" } }, a.target),
        a.justification ? h("p", { class: "just" }, a.justification) : null),
      h("span", { class: "quien" }, quien)));
  if (!a.permitida) {
    tarjeta.append(h("p", { class: "just" }, a.nota || "La política no permite actuar aquí: solo se escala."));
    return tarjeta;
  }
  if (hecha) {
    tarjeta.append(h("div", { class: "ok-caja" }, `Ejecutada · aprobó ${hecha.approved_by} · ${hecha.result || "ok"}`));
    return tarjeta;
  }
  if (rechazada) return tarjeta;

  const mensaje = h("div");
  let nombre = null;
  const ejecutar = async () => {
    mensaje.replaceChildren();
    try {
      await api.ejecutar(r.alert_id, indice, { aprobador: nombre?.value ?? "", motivo: "" });
      aviso(`${a.action} ejecutada (simulada)`, "ok");
      recargar();
    } catch (e) {
      mensaje.replaceChildren(h("div", { class: "err-caja" }, e.message));
    }
  };
  const botones = h("div", { class: "fila-btn" });
  if (a.requires_approval) {
    const boton = botonMantener("Mantén pulsado para firmar", ejecutar, true);
    nombre = h("input", { type: "text", placeholder: "N2 - Nombre Apellido", "aria-label": "Nombre de quien aprueba", autocomplete: "off",
      onInput: () => { boton.disabled = !nombre.value.trim(); } });
    tarjeta.append(h("div", { class: "firma" }, h("label", { class: "campo" }, "Firma de quien aprueba", nombre), boton));
  } else {
    botones.append(h("button", { class: "btn go sm", type: "button", onClick: ejecutar }, "Ejecutar (N1)"));
  }
  botones.append(h("button", { class: "btn sm", type: "button", onClick: async () => {
    await api.decidir(r.alert_id, { tipo: "rechazar_accion", indice, por: nombre?.value ?? "" }).catch((e) => aviso(e.message));
    recargar();
  } }, "Rechazar"));
  tarjeta.append(botones, mensaje);
  return tarjeta;
}

function formularioCorregir(r, recargar) {
  const p = r.politica;
  if (!p) return null;
  const opcion = (valor, textoOpcion, elegido) => h("option", { value: valor, selected: elegido }, textoOpcion ?? valor);
  const ver = h("select", { "aria-label": "Veredicto correcto" }, ...Object.keys(VEREDICTO).map((v) => opcion(v, veredicto(v), v === p.veredicto)));
  const sev = h("select", { "aria-label": "Gravedad correcta" }, opcion("", "Gravedad: sin cambios", true), ...SEVERIDADES.slice().reverse().map((s) => opcion(s, gravedad(s))));
  const motivo = h("input", { type: "text", placeholder: "Por qué lo corriges", "aria-label": "Motivo de la corrección", autocomplete: "off" });
  const por = h("input", { type: "text", placeholder: "Tu nombre y rol", "aria-label": "Tu nombre", autocomplete: "off" });
  const enviar = async () => {
    try {
      await api.decidir(r.alert_id, { tipo: "corregir", por: por.value, motivo: motivo.value, veredicto: ver.value, severidad: sev.value });
      aviso("Corrección anotada", "ok");
      recargar();
    } catch (e) { aviso(e.message); }
  };
  return h("details", { class: "pliego" }, h("summary", {}, "No estoy de acuerdo: corregir el veredicto"),
    h("div", { class: "corregir" }, ver, sev, motivo, por,
      h("div", {}, h("button", { class: "btn sm", type: "button", onClick: enviar }, "Registrar corrección"))));
}

function persona(r, recargar) {
  const t = r.ticket;
  if (!t) return bloque("Contención · firma una persona", ["N4"], null, h("p", { class: "nota" }, "Sin ticket: no hay nada que decidir."));
  const acciones = (t.recommended_actions || []).map((a, i) => [a, i]);
  const contencion = acciones.filter(([a]) => !["close", "human_review"].includes(a.action));
  const decision = r.politica?.decision;
  const humano = r.humano || [];
  const cerrada = humano.find((d) => d.tipo === "cerrar");
  const aN2 = humano.find((d) => d.tipo === "escalar_n2");
  const nombre = h("input", { type: "text", placeholder: "Tu nombre y rol", "aria-label": "Tu nombre", autocomplete: "off" });
  const decidir = (tipo) => async () => {
    try { await api.decidir(r.alert_id, { tipo, por: nombre.value }); recargar(); } catch (e) { aviso(e.message); }
  };
  const flujo = cerrada || aN2
    ? h("div", { class: "ok-caja" }, cerrada ? `Cierre confirmado por ${cerrada.por}` : `Pasada a N2 por ${aN2.por}`)
    : h("div", { class: "firma" },
      h("label", { class: "campo" }, decision === "cerrar" ? "Firma de quien cierra" : "Firma de quien decide", nombre),
      h("div", { class: "fila-btn" },
        decision === "cerrar" ? h("button", { class: "btn go sm", type: "button", onClick: decidir("cerrar") }, "Confirmar el cierre")
          : h("button", { class: "btn go sm", type: "button", onClick: decidir("escalar_n2") }, "Pasar a N2"),
        decision === "cerrar" ? h("button", { class: "btn sm", type: "button", onClick: decidir("escalar_n2") }, "No: escalar a N2") : null));
  return bloque("Contención · firma una persona", ["N4"], contencion.length ? `${contencion.length} acciones` : null,
    ...(contencion.length ? contencion.map(([a, i]) => tarjetaAccion(r, a, i, recargar)) : [h("p", { class: "nota" }, "La política no propone contención para esta alerta.")]),
    flujo,
    formularioCorregir(r, recargar),
    h("div", { class: "fila-btn" },
      h("button", { class: "btn sm", type: "button", onClick: () => descargar(`${t.ticket_id}.json`, t) }, "Ticket (JSON)"),
      (r.ticket_errores || []).length ? chip("Ticket con errores de esquema", "c-med") : chip("Cumple el esquema de Deloitte", "c-co")));
}

// --- Cabecera: conclusión y quién decide qué ------------------------------------------------------

function cabecera(r, meta) {
  const t = r.ticket, p = r.politica, ia = r.llm?.analisis;
  const m = meta ?? r.meta ?? {};
  return h("section", { class: "detalle-cab entra" },
    h("div", { class: "meta" }, h("span", { class: "cap" }, [r.alert_id, m.source_product, m.rule_id, m.created_at ? hora(m.created_at) : null].filter(Boolean).join(" · ")),
      p ? h("span", { class: `sello ${p.decision}`, style: { marginLeft: "auto" } }, SELLO[p.decision] ?? p.decision) : null),
    h("h1", {}, t?.title ?? m.rule_name ?? r.alert_id),
    ia?.summary ? h("p", { class: "entradilla" }, h("span", { class: "ia-marca" }, "✦ "), ia.summary) : null);
}

function reparto(r) {
  const ia = r.llm?.analisis;
  const p = r.politica;
  const humano = r.humano || [];
  const cerrada = humano.find((d) => d.tipo === "cerrar");
  const aN2 = humano.find((d) => d.tipo === "escalar_n2");
  const correccion = [...humano].reverse().find((d) => d.tipo === "corregir");
  const corregido = p && p.veredicto_llm && p.veredicto_llm !== p.veredicto;
  const pendientes = (r.ticket?.recommended_actions || []).filter((a) => !["close", "human_review"].includes(a.action) && a.permitida && !ejecutada(r.ticket, a)).length;
  let persona;
  if (correccion) persona = [h("div", { class: "q" }, `Corrigió: ${veredicto(correccion.veredicto)}`), h("small", {}, `${correccion.por}: ${cortar(correccion.motivo, 80)}`)];
  else if (cerrada || aN2) persona = [h("div", { class: "q" }, cerrada ? "Cierre confirmado" : "Pasada a N2"), h("small", {}, (cerrada ?? aN2).por)];
  else persona = [h("div", { class: "q" }, p?.decision === "cerrar" ? "Confirmar el cierre" : pendientes ? `${pendientes} acciones esperan tu firma` : "Decidir")];
  return h("section", { class: "reparto entra", "aria-label": "Quién decide qué" },
    h("div", {}, h("span", { class: "cap" }, "✦ La IA propone"), h("div", { class: "q ia-voz" }, ia ? veredicto(ia.verdict) : "Sin análisis"),
      h("small", {}, ia ? `confianza ${Number(ia.confidence).toFixed(2).replace(".", ",")} · ${(ia.evidence || []).length} eventos citados` : "")),
    h("div", {}, h("span", { class: "cap" }, "{ } El código decide"),
      h("div", { class: "q", style: { color: p?.decision === "escalar" ? "var(--crit)" : p?.decision === "revisar" ? "var(--med)" : "var(--ok)" } },
        p ? `${corregido ? `${veredicto(p.veredicto)} · ` : ""}${gravedad(p.severidad_final)} · ${SELLO[p.decision] ?? DECISION[p.decision] ?? p.decision}` : "—"),
      h("small", {}, p ? [corregido ? "corrige a la IA" : null, p.sla?.tiempo_triaje ? `plazo ${p.sla.tiempo_triaje}` : null].filter(Boolean).join(" · ") : "")),
    h("div", { class: "pe" }, h("span", { class: "cap" }, "✍ Tú decides"), ...persona));
}

// --- Vista -------------------------------------------------------------------------------------------

export function montarDetalle(raiz, id) {
  let vivo = true;
  let baja = () => {};
  const cargar = async () => {
    const meta = estado.filas.get(id)?.meta ?? await api.alerta(id).catch(() => null);
    const r = await api.resultado(id).catch(() => null);
    if (!vivo) return;
    if (!r) return mostrarSinTriar(meta);
    if (r.error) return raiz.replaceChildren(volver(), h("p", { class: "err-caja" }, r.error));
    const recargar = async () => { await refrescarResultado(id); cargar(); };
    raiz.replaceChildren(volver(), cabecera(r, meta), reparto(r),
      h("div", { class: "exp" },
        h("div", { class: "izq" }, porQue(r), cronologia(r), implicados(r), dudas(r), grupoAtaque(id), panelInforme(id, r),
          h("section", { class: "bloque" }, evidenciaCompleta(r), alertaOriginal(id, r))),
        h("aside", { class: "der" }, consultas(r), gravedadBloque(r), persona(r, recargar))));
  };

  function mostrarSinTriar(meta) {
    const f = estado.filas.get(id);
    const boton = h("button", { class: "btn go", type: "button", onClick: () => triarFilas([id]) }, "Triar esta alerta");
    raiz.replaceChildren(volver(),
      h("section", { class: "detalle-cab entra" }, h("div", { class: "cap" }, [id, meta?.source_product, meta?.rule_id].filter(Boolean).join(" · ")),
        h("h1", {}, meta?.rule_name ?? id)),
      h("div", { class: "card vacio" }, h("p", {}, f?.etapa && f.etapa !== "pendiente" && f.etapa !== "error" ? "Triando…" : f?.error ?? "Esta alerta aún no se ha triado."), boton));
    baja = suscribir(() => { if (estado.filas.get(id)?.etapa === "listo") { baja(); cargar(); } });
  }

  cargar();
  return () => { vivo = false; baja(); };
}

function volver() {
  return h("a", { class: "btn sm", href: "#/", style: { marginTop: "10px" } }, icono("atras", 16), "Volver a la bandeja");
}
