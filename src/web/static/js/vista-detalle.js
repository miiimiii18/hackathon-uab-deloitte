import { api } from "./api.js";
import { anilloConfianza, h, icono } from "./dom.js";
import { estado, refrescarResultado, suscribir, triarFilas } from "./estado.js";
import { aviso, cortar, DECISION, descargar, hora, SEVERIDADES, siNo } from "./util.js";

const VEREDICTOS = ["true_positive", "benign_true_positive", "false_positive", "needs_more_info"];

const esObjeto = (v) => v && typeof v === "object" && !Array.isArray(v);
const kv = (clave, valor) => h("div", { class: "kv" }, h("span", {}, clave), h("span", {}, valor));
const mono = (t) => h("span", { class: "m", style: { fontSize: "12.5px" } }, t);
const chip = (texto, clase = "") => h("span", { class: `chip ${clase}` }, texto);
const crudo = (objeto) => h("details", {}, h("summary", {}, "Ver datos en bruto"), h("pre", { class: "json" }, JSON.stringify(objeto, null, 2)));

function panel(clase, rol, titulo, derecha, ...contenido) {
  const etiqueta = { co: ["Código", "c-co"], ia: ["IA", "c-ia"], pe: ["Persona", "c-pe"] }[rol];
  return h("article", { class: `card pn entra ${clase}`, "aria-label": titulo },
    h("h2", {}, h("span", {}, chip(etiqueta[0], etiqueta[1]), titulo), derecha ? h("span", { class: "m", style: { fontSize: "12px", color: "var(--mu)", fontWeight: 400 } }, derecha) : null),
    ...contenido);
}

// --- Pasos del triaje (diapositiva 5 del reto) --------------------------------------------

const PASOS = [["Entender", "co"], ["Contexto", "co"], ["Enriquecer", "co"], ["Correlar", "co"], ["Decidir", "ia"], ["Priorizar", "co"], ["Actuar", "pe"]];

function pasos(pendiente) {
  return h("nav", { class: "pasos entra", "aria-label": "Pasos del triaje" }, ...PASOS.map(([nombre, rol], i) => {
    const ultimo = i === PASOS.length - 1;
    const ahora = ultimo && pendiente;
    return h("span", { class: `${rol === "ia" ? "p-ia" : rol === "pe" ? "p-pe" : ""} ${ahora ? "ahora" : ""}` },
      h("b", {}, ahora ? null : icono("check", 10, 4)), h("em", {}, ahora ? "Actuar · espera tu decisión" : nombre));
  }));
}

// --- Qué ha consultado ---------------------------------------------------------------------

function parametros(p) {
  return Object.entries(p || {}).filter(([k]) => k !== "limit").map(([k, v]) => `${k}=${v}`).join(" ");
}

function consultas(r) {
  const traza = r.traza || [];
  const maximo = Math.max(1, ...traza.map((t) => t.ms));
  const total = traza.reduce((s, t) => s + t.ms, 0);
  const filas = traza.map((t, i) => {
    let estadoTag;
    if (t.desconocido) estadoTag = h("span", { class: "tg unk" }, "404 · desconocido");
    else if (t.cache) estadoTag = h("span", { class: "tg" }, "caché");
    else if (t.estado && t.estado !== 200) estadoTag = h("span", { class: "tg bad" }, `error ${t.estado}`);
    else estadoTag = h("span", { class: "tg ok" }, `${t.resultados} resultado${t.resultados === 1 ? "" : "s"}`);
    return h("div", { class: "q" },
      h("span", { class: "m" }, t.consulta, " ", h("span", { class: "par" }, cortar(parametros(t.parametros), 60))),
      h("span", {}, h("span", { class: "cinta", style: { width: `${Math.max(4, (t.ms / maximo) * 100)}%`, animationDelay: `${Math.min(i, 20) * 0.05}s` } })),
      h("span", { class: "m", style: { color: "var(--mu)" } }, `${t.ms} ms`),
      h("span", {}, estadoTag));
  });
  return panel("", "co", "Qué ha consultado", `${traza.length} consultas · ${(total / 1000).toFixed(1)} s`,
    h("div", { class: "scroll" }, h("div", { class: "tope" }, ...filas)));
}

// --- En qué se basa ------------------------------------------------------------------------

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
  const hayDesconocido = lista.some((i) => i.estado === "unknown");
  return h("div", {}, h("h3", {}, "Inteligencia"),
    ...(lista.length ? lista.map((i) => {
      const geo = i.geo ? [i.geo.country, i.geo.city].filter(Boolean).join(", ") : "";
      return h("div", {}, kv(mono(cortar(i.indicador, 30)), h("span", { class: `tg ${{ malicious: "bad", suspicious: "unk", unknown: "unk", clean: "clean" }[i.estado] ?? ""}` }, i.estado)),
        geo ? kv("Origen", cortar(`${geo} · ${i.geo.as_org ?? ""}`, 46)) : null);
    }) : [h("p", { class: "nota" }, "Sin indicadores que enriquecer")]),
    hayDesconocido ? h("p", { class: "aviso" }, "Desconocido no es limpio: no resta sospecha.") : null,
    lista.length ? crudo(lista) : null);
}

function bloqueContexto(ev) {
  const sandbox = Object.entries(ev.sandbox || {});
  const cambios = ev.cambios_aprobados || [];
  return h("div", {}, h("h3", {}, "Sandbox y cambios"),
    ...sandbox.map(([sha, s]) => (esObjeto(s)
      ? kv(`Sandbox ${sha.slice(0, 8)}…`, h("b", {}, `${s.malware_family ?? s.verdict ?? "informe"}${s.score != null ? ` · ${s.score}` : ""}`))
      : kv(`Sandbox ${sha.slice(0, 8)}…`, h("span", { class: "tg unk" }, "sin informe")))),
    kv("Cambios aprobados", cambios.length ? h("b", {}, cambios.map((c) => c.id ?? c.change_id ?? "?").join(", ")) : "Ninguno"),
    ...cambios.map((c) => h("p", { class: "nota" }, cortar(`${c.id ?? ""}: ${c.titulo ?? c.title ?? c.detalle ?? ""}`, 90))),
    kv("Eventos citados", `${(ev.eventos_citados_en_la_alerta || []).length}`));
}

function bloqueLogs(ev) {
  const logs = ev.contexto_logs || [];
  if (!logs.length) return null;
  return h("div", { style: { gridColumn: "1 / -1" } }, h("h3", {}, "Logs consultados (±24 h)"),
    ...logs.map((l) => h("div", {},
      kv(h("span", {}, mono(l.fuente), " ", h("span", { style: { color: "var(--mu)" } }, cortar(l.busqueda, 40))),
        h("b", {}, `${l.total}${l.truncado ? "+" : ""} evento${l.total === 1 ? "" : "s"}`)),
      l.muestra?.length ? crudo(l.muestra) : null)));
}

function base(r) {
  const ev = r.evidencia || {};
  return panel("", "co", "En qué se basa", null,
    h("div", { class: "base" }, bloqueActivos(ev), bloqueUsuarios(ev), bloqueInteligencia(ev), bloqueContexto(ev), bloqueLogs(ev)),
    (ev.eventos_citados_en_la_alerta || []).length ? crudo(ev.eventos_citados_en_la_alerta) : null,
    (ev.notas || []).length ? h("p", { class: "nota" }, ev.notas.join(" ")) : null);
}

// --- Qué propone la IA ---------------------------------------------------------------------

const SENALES = {
  ejecucion_o_acceso_confirmado: "Ejecución o acceso confirmado",
  identidad_vip_o_privilegiada: "Identidad VIP o privilegiada",
  datos_personales_o_pagos: "Datos personales o pagos",
  bloqueado_sin_actividad_posterior: "Bloqueado sin actividad posterior",
  actividad_autorizada: "Actividad autorizada",
};

function propuestaIA(r) {
  const ia = r.llm?.analisis;
  if (!ia) return panel("ia", "ia", "Qué propone", null, h("p", { class: "nota" }, "Sin análisis de la IA en este resultado."));
  const senales = Object.entries(SENALES).map(([k, texto]) => h("span", { class: `sen ${ia.senales?.[k] ? "si" : ""}` }, h("b"), texto));
  return panel("ia", "ia", "Qué propone", `${r.llm.modelo} · ${Math.round(r.llm.segundos)} s · ${r.llm.tokens_entrada ?? "?"} tokens`,
    h("div", { class: "ia-cab" }, anilloConfianza(ia.confidence),
      h("div", { style: { flex: "1 1 360px", minWidth: 0 } }, h("div", { class: "m", style: { fontSize: "18px", marginBottom: "6px" } }, ia.verdict), h("p", {}, ia.summary))),
    ia.evidence?.length ? h("div", { class: "scroll" }, h("div", { class: "tope" }, ...ia.evidence.map((e) => h("div", { class: "ev" }, mono(e.source), h("span", { class: "m", style: { color: "var(--mu)", fontSize: "12px" } }, e.event_id), h("span", {}, e.finding))))) : null,
    h("div", { class: "senales" }, ...senales),
    (ia.mitre || []).length ? h("div", { class: "mitre" }, ...ia.mitre.map((m) => chip(m, "m"))) : null,
    (ia.open_questions || []).length ? h("div", {}, h("h3", { style: { margin: "0 0 4px", fontSize: "12px", color: "var(--mu)", letterSpacing: ".08em", textTransform: "uppercase" } }, "Preguntas abiertas"), h("ul", { class: "lista" }, ...ia.open_questions.map((q) => h("li", {}, q)))) : null);
}

// --- Lo que decide el código ---------------------------------------------------------------

function politica(r) {
  const p = r.politica;
  if (!p) return panel("", "co", "Decide la política", null, h("p", { class: "nota" }, "Este resultado solo tiene evidencia."));
  const aj = Number(p.ajuste) || 0;
  const sv = (s) => h("span", { class: `sv ${s}` }, s);
  const corregido = p.veredicto_llm && p.veredicto_llm !== p.veredicto;
  return panel("", "co", "Decide la política", null,
    h("div", { class: "ecu" },
      h("span", { class: "ecc" }, "Regla ", sv(p.severidad_regla)), h("span", { class: "op" }, "×"),
      h("span", { class: "ecc" }, "Activo ", h("b", {}, p.criticidad)), h("span", { class: "op" }, "="),
      h("span", { class: "ecc" }, sv(p.severidad_base)), h("span", { class: "op" }, aj >= 0 ? "+" : "−"),
      h("span", { class: "ecc", style: aj ? { borderColor: "#6d2a2a" } : {} }, "ajuste ", h("b", { style: { color: aj ? "#ff9a9a" : "inherit" } }, aj > 0 ? `+${aj}` : String(aj))), h("span", { class: "op" }, "="),
      h("span", { class: `sv ${p.severidad_final}`, style: { height: "34px", fontSize: "13px" } }, p.severidad_final)),
    h("p", { class: "nota" }, p.razon_severidad),
    h("div", {},
      kv("Veredicto final", h("b", { class: "m" }, p.veredicto)),
      corregido ? kv("La IA dijo", h("span", { class: "m", style: { color: "var(--ia)", textDecoration: "line-through" } }, p.veredicto_llm)) : null,
      p.autorizacion ? kv("Autorización verificada", mono(p.autorizacion)) : null,
      kv("Decisión", h("b", { class: `tg ${p.decision}` }, DECISION[p.decision] ?? p.decision)),
      (p.motivos_escalado || []).length ? kv("Motivos", h("span", {}, p.motivos_escalado.join(" · "))) : null,
      p.sla ? kv("SLA", h("span", {}, [p.sla.tiempo_triaje, p.sla.escalado].filter(Boolean).join(" · "))) : null,
      p.sla?.notificar ? kv("Notificar", p.sla.notificar) : null),
    ...(p.avisos || []).map((a) => h("div", { class: corregido ? "err-caja" : "ok-caja", style: corregido ? {} : { background: "#2a2412", borderColor: "#6b5217", color: "#f5d84a" } }, a)),
    !(p.avisos || []).length ? kv("Avisos", "Ninguno") : null);
}

// --- Alertas del mismo ataque --------------------------------------------------------------

function grupoAtaque(id) {
  const g = estado.grupos.get(id);
  if (!g) return null;
  const t = g.ticket;
  return panel("", "co", "Mismo ataque", `${g.alert_ids.length} alertas · ${g.severidad}`,
    h("p", { class: "nota" }, t.escalation.reason),
    h("div", {}, ...g.alert_ids.map((a) => h("a", { class: "m", href: `#/alerta/${encodeURIComponent(a)}`, style: { display: "block", fontSize: "12.5px", padding: "3px 0" } }, a === id ? `${a} · esta` : a))),
    kv("Reglas", cortar(g.reglas.join(", "), 80)),
    kv("Las une", cortar(g.entidades.join(" · "), 90)),
    kv("Ticket único", mono(t.ticket_id)),
    h("button", { class: "btn sm", type: "button", onClick: () => descargar(`${t.ticket_id}.json`, t) }, "Ticket único JSON"));
}

// --- Quién decide qué (siempre a la vista) -------------------------------------------------

function reparto(r) {
  const ia = r.llm?.analisis;
  const p = r.politica;
  const humano = r.humano || [];
  const cerrada = humano.find((d) => d.tipo === "cerrar");
  const aN2 = humano.find((d) => d.tipo === "escalar_n2");
  const correccion = [...humano].reverse().find((d) => d.tipo === "corregir");
  const corregido = p && p.veredicto_llm && p.veredicto_llm !== p.veredicto;
  const tarjeta = (clase, chipTexto, ...lineas) => h("div", { class: clase }, chip(chipTexto, `c-${clase}`), ...lineas);
  let persona;
  if (correccion) persona = [h("b", {}, `Corrigió: ${correccion.veredicto}${correccion.severidad ? ` · ${correccion.severidad}` : ""}`), h("small", {}, `${correccion.por}: ${cortar(correccion.motivo, 90)}`)];
  else if (cerrada || aN2) persona = [h("b", {}, cerrada ? "Cierre confirmado" : "Pasada a N2"), h("small", {}, (cerrada ?? aN2).por)];
  else persona = [h("b", {}, p?.decision === "cerrar" ? "Pendiente: confirmar el cierre" : "Pendiente de decidir"), h("small", {}, "Aprueba o rechaza acciones, pasa a N2, cierra o corrige el veredicto")];
  return h("section", { class: "reparto entra", "aria-label": "Quién decide qué" },
    tarjeta("ia", "IA propone", h("b", { class: "m" }, ia ? `${ia.verdict} · confianza ${Number(ia.confidence).toFixed(2)}` : "Sin análisis"), h("small", {}, "Veredicto, argumentos y acciones sugeridas. No ejecuta nada.")),
    tarjeta("co", "Código decide", h("b", { class: "m" }, p ? `${p.veredicto}${corregido ? " (corrige a la IA)" : ""} · ${p.severidad_final} · ${DECISION[p.decision] ?? p.decision}` : "—"), h("small", {}, "Severidad, escalado y permisos de contención, con reglas fijas.")),
    tarjeta("pe", "Persona decide", ...persona));
}

function alertaOriginal(id, r) {
  const cuerpo = h("div", {}, h("p", { class: "nota" }, "Cargando…"));
  const pintar = (a) => cuerpo.replaceChildren(h("pre", { class: "json" }, JSON.stringify(a, null, 2)));
  if (r.alerta) pintar(r.alerta);
  else api.original(id).then(pintar).catch((e) => cuerpo.replaceChildren(h("p", { class: "nota" }, `No se pudo cargar la alerta: ${e.message}`)));
  return panel("", "co", "Alerta original", "tal como llegó", cuerpo);
}

// --- Lo que decide la persona --------------------------------------------------------------

function botonMantener(texto, alCompletar, deshabilitado) {
  const relleno = h("i");
  const boton = h("button", { class: "mantener", type: "button", disabled: deshabilitado }, relleno, h("span", {}, texto));
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
  const clase = !a.permitida ? "prohibida" : hecha ? "hecha" : a.requires_approval ? "espera" : "";
  const aprobador = !a.permitida ? "Prohibida" : a.requires_approval ? `Aprueba ${a.aprobador}` : "Lo ejecuta el N1";
  const cab = h("div", { class: "cab" },
    h("div", { style: { minWidth: 0 } }, h("b", { class: "m" }, a.action),
      h("div", { class: "m", style: { fontSize: "12.5px", color: "var(--mu)", overflowWrap: "anywhere" } }, a.target)),
    hecha ? chip("Ejecutada", "c-pe") : rechazada ? chip("Rechazada") : !a.permitida ? chip("Prohibida · red OT", "c-co") : chip(aprobador, a.requires_approval ? "c-med" : "c-co"));
  const tarjeta = h("div", { class: `acto ${clase}` }, cab, a.justification ? h("p", { class: "just" }, a.justification) : null);
  if (!a.permitida) {
    tarjeta.append(h("p", { class: "just" }, a.nota || "La política no permite actuar aquí: solo se escala."));
    return tarjeta;
  }
  if (hecha) {
    tarjeta.append(h("div", { class: "ok-caja" }, `Ejecutada por ${hecha.approved_by} · ${hecha.result || "ok"}`));
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
  if (a.requires_approval) {
    const boton = botonMantener("Mantén pulsado para aprobar", ejecutar, true);
    nombre = h("input", { type: "text", placeholder: "N2 - Nombre Apellido", "aria-label": "Nombre de quien aprueba", autocomplete: "off",
      onInput: () => { boton.disabled = !nombre.value.trim(); } });
    tarjeta.append(h("label", { class: "campo" }, "Quién aprueba", nombre), boton);
  } else {
    tarjeta.append(h("button", { class: "btn go sm", type: "button", onClick: ejecutar }, "Ejecutar"));
  }
  tarjeta.append(h("button", { class: "btn sm", type: "button", onClick: async () => {
    await api.decidir(r.alert_id, { tipo: "rechazar_accion", indice, por: nombre?.value ?? "" }).catch((e) => aviso(e.message));
    recargar();
  } }, "Rechazar"), mensaje);
  return tarjeta;
}

function formularioCorregir(r, recargar) {
  const p = r.politica;
  if (!p) return null;
  const opcion = (valor, texto, elegido) => h("option", { value: valor, selected: elegido }, texto ?? valor);
  const veredicto = h("select", { "aria-label": "Veredicto correcto" }, ...VEREDICTOS.map((v) => opcion(v, v, v === p.veredicto)));
  const severidad = h("select", { "aria-label": "Severidad correcta" }, opcion("", "Severidad: sin cambios", true), ...SEVERIDADES.slice().reverse().map((s) => opcion(s)));
  const motivo = h("input", { type: "text", placeholder: "Por qué lo corriges", "aria-label": "Motivo de la corrección", autocomplete: "off" });
  const por = h("input", { type: "text", placeholder: "Tu nombre y rol", "aria-label": "Tu nombre", autocomplete: "off" });
  const enviar = async () => {
    try {
      await api.decidir(r.alert_id, { tipo: "corregir", por: por.value, motivo: motivo.value, veredicto: veredicto.value, severidad: severidad.value });
      aviso("Corrección anotada", "ok");
      recargar();
    } catch (e) { aviso(e.message); }
  };
  return h("details", {}, h("summary", {}, "No estoy de acuerdo: corregir el veredicto"),
    h("div", { class: "corregir" }, veredicto, severidad, motivo, por,
      h("button", { class: "btn sm", type: "button", onClick: enviar }, "Registrar corrección"),
      h("p", { class: "nota" }, "Queda anotada con tu nombre. No cambia lo que calculó el código ni ejecuta nada.")));
}

function persona(r, recargar) {
  const t = r.ticket;
  if (!t) return panel("pe", "pe", "Tu decisión", null, h("p", { class: "nota" }, "Sin ticket: no hay nada que decidir."));
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
  const flujo = h("div", { class: "acto" },
    cerrada || aN2
      ? h("div", { class: "ok-caja" }, cerrada ? `Cierre confirmado por ${cerrada.por}` : `Pasada a N2 por ${aN2.por}`)
      : [h("label", { class: "campo" }, decision === "cerrar" ? "Quién cierra" : "Quién decide", nombre),
        h("div", { class: "fila-btn" },
          decision === "cerrar" ? h("button", { class: "btn go sm", type: "button", onClick: decidir("cerrar") }, "Confirmar cierre")
            : h("button", { class: "btn go sm", type: "button", onClick: decidir("escalar_n2") }, "Pasar a N2"),
          decision === "cerrar" ? h("button", { class: "btn sm", type: "button", onClick: decidir("escalar_n2") }, "Escalar a N2") : null)]);
  const corregir = formularioCorregir(r, recargar);
  return panel("pe", "pe", "Tu decisión", null,
    ...(contencion.length ? contencion.map(([a, i]) => tarjetaAccion(r, a, i, recargar)) : [h("p", { class: "nota" }, "La política no propone contención para esta alerta.")]),
    flujo,
    corregir,
    h("p", { class: "nota" }, "En la red OT no se actúa: solo se escala. La contención es simulada y queda registrada con el nombre de quien aprueba."),
    h("div", { class: "fila-btn" },
      h("button", { class: "btn sm", type: "button", onClick: () => descargar(`${t.ticket_id}.json`, t) }, "Ticket JSON"),
      (r.ticket_errores || []).length ? chip("Ticket con errores de esquema", "c-med") : chip("Cumple el esquema de Deloitte", "c-co")));
}

// --- Vista ---------------------------------------------------------------------------------

function cabecera(r, meta) {
  const t = r.ticket, p = r.politica;
  const m = meta ?? r.meta ?? {};
  return h("section", { class: "detalle-cab entra" },
    h("div", { style: { flex: "1 1 640px", minWidth: 0 } },
      h("div", { class: "meta" }, mono(r.alert_id), m.source_product ? chip(`${m.source_product} · ${m.rule_id}`) : null, m.created_at ? chip(hora(m.created_at)) : null),
      h("h1", { class: "d" }, t?.title ?? m.rule_name ?? r.alert_id)),
    p ? h("div", { class: "meta" }, h("span", { class: "m", style: { fontSize: "13px" } }, p.veredicto),
      h("span", { class: `sv ${p.severidad_final}`, style: { height: "30px", fontSize: "13px" } }, p.severidad_final),
      h("span", { class: `tg ${p.decision}`, style: { minHeight: "30px" } }, DECISION[p.decision])) : null);
}

export function montarDetalle(raiz, id) {
  let vivo = true;
  let baja = () => {};
  const cargar = async () => {
    const meta = estado.filas.get(id)?.meta ?? await api.alerta(id).catch(() => null);
    const r = await api.resultado(id).catch(() => null);
    if (!vivo) return;
    if (!r) return mostrarSinTriar(meta);
    if (r.error) return raiz.replaceChildren(volver(), h("p", { class: "err-caja" }, r.error));
    const pendiente = (r.politica?.decision === "escalar" || r.politica?.decision === "revisar")
      && !(r.humano || []).some((d) => d.tipo === "cerrar" || d.tipo === "escalar_n2");
    const recargar = async () => { await refrescarResultado(id); cargar(); };
    raiz.replaceChildren(volver(), cabecera(r, meta), pasos(pendiente), reparto(r),
      h("div", { class: "rejilla" },
        h("div", { class: "col-izq" }, consultas(r), base(r), propuestaIA(r), alertaOriginal(id, r)),
        h("aside", { class: "col-der" }, grupoAtaque(id), politica(r), persona(r, recargar))));
  };

  function mostrarSinTriar(meta) {
    const f = estado.filas.get(id);
    const boton = h("button", { class: "btn go", type: "button", onClick: () => triarFilas([id]) }, "Triar esta alerta");
    raiz.replaceChildren(volver(),
      h("section", { class: "detalle-cab entra" }, h("div", {}, h("div", { class: "meta" }, mono(id), meta ? chip(`${meta.source_product} · ${meta.rule_id}`) : null),
        h("h1", { class: "d" }, meta?.rule_name ?? id))),
      h("div", { class: "card vacio" }, h("p", {}, f?.etapa && f.etapa !== "pendiente" && f.etapa !== "error" ? "Triando…" : f?.error ?? "Esta alerta aún no se ha triado."), boton));
    baja = suscribir(() => { if (estado.filas.get(id)?.etapa === "listo") { baja(); cargar(); } });
  }

  cargar();
  return () => { vivo = false; baja(); };
}

function volver() {
  return h("a", { class: "btn sm", href: "#/", style: { marginBottom: "10px" } }, icono("atras", 16), "Cola de alertas");
}
