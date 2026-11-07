import { h } from "./dom.js";
import { abrirPanel } from "./panel.js";
import { estado, restablecerCola, suscribir, triarFilas } from "./estado.js";
import { DECISION, ETAPA, minutos, SEVERIDADES } from "./util.js";

const VEREDICTOS = ["true_positive", "benign_true_positive", "false_positive", "needs_more_info"];
const ESTADOS = [["escalar", "Escalar a N2"], ["revisar", "Revisar"], ["cerrar", "Cerrar"], ["pendiente", "Sin triar"], ["error", "Con error"]];
// Se guardan fuera de la vista para que sigan al volver desde el detalle.
const filtros = { regla: "", severidad: "", veredicto: "", estado: "" };

function pasaFiltros(f) {
  const listo = f.etapa === "listo";
  const r = f.resumen;
  if (filtros.regla && f.meta?.rule_id !== filtros.regla) return false;
  if (filtros.severidad && !(listo && r.severidad === filtros.severidad)) return false;
  if (filtros.veredicto && !(listo && r.veredicto === filtros.veredicto)) return false;
  if (filtros.estado) {
    const actual = listo ? r.decision : f.etapa === "error" ? "error" : "pendiente";
    if (actual !== filtros.estado) return false;
  }
  return true;
}

const SEGMENTOS = {
  pendiente: ["o", "o", "o", "o"],
  evidencia: ["a", "o", "o", "o"],
  ia: ["d", "a", "o", "o"],
  politica: ["d", "d", "a", "o"],
  error: ["x", "x", "x", "x"],
};

function segmentos(f) {
  if (f.etapa !== "listo") return SEGMENTOS[f.etapa];
  const r = f.resumen;
  const espera = (r.decision === "escalar" || r.decision === "revisar") && !r.resuelta;
  return ["d", "d", "d", espera ? "w" : "d"];
}

function crearFila(id) {
  const r = {};
  const el = h("a", { class: "fila", href: `#/alerta/${encodeURIComponent(id)}`, role: "row" },
    r.barra = h("span", { class: "barra", "aria-hidden": "true" }),
    h("span", { class: "id", role: "cell" }, id),
    h("span", { role: "cell" }, r.tit = h("span", { class: "tit" }), h("br"), r.sub = h("span", { class: "sub" })),
    r.pp = h("span", { class: "pp", role: "cell" }, h("i"), h("i"), h("i"), h("i")),
    r.ver = h("span", { role: "cell", style: { display: "flex", flexDirection: "column", gap: "3px" } }),
    r.sev = h("span", { role: "cell" }),
    r.dec = h("span", { role: "cell" }),
    r.conf = h("span", { class: "m", role: "cell", style: { fontSize: "12.5px" } }),
    r.seg = h("span", { class: "m", role: "cell", style: { fontSize: "12.5px", color: "var(--mu)" } }));
  el.refs = r;
  return el;
}

function actualizarFila(el, f) {
  const r = el.refs;
  const res = f.resumen;
  const listo = f.etapa === "listo";
  const enCurso = ["evidencia", "ia", "politica"].includes(f.etapa);

  r.barra.className = `barra ${listo ? res.severidad : enCurso ? "run" : f.etapa === "error" ? "fallo" : ""}`;
  r.tit.textContent = res?.titulo ?? f.meta?.rule_name ?? f.id;
  r.sub.textContent = f.error ? "" : [f.meta?.rule_id, f.meta?.source_product].filter(Boolean).join(" · ");
  if (f.error) {
    r.sub.replaceChildren(h("span", { class: "err" }, f.error));
  }
  const g = estado.grupos.get(f.id);
  if (g && listo) r.sub.append(" ", h("span", { class: "chip c-med", title: `Mismo ataque: ${g.alert_ids.join(", ")}` }, `Mismo ataque · ${g.alert_ids.length} alertas`));
  [...r.pp.children].forEach((seg, i) => { seg.className = segmentos(f)[i]; });

  r.ver.replaceChildren();
  r.sev.replaceChildren();
  r.dec.replaceChildren();
  r.conf.textContent = "";
  r.seg.textContent = "";
  if (listo) {
    r.ver.append(h("span", { class: "m", style: { fontSize: "12px" } }, res.veredicto ?? "—"));
    if (res.veredicto_llm && res.veredicto_llm !== res.veredicto) r.ver.append(h("span", { class: "corregido", title: "El código corrigió a la IA" }, `IA: ${res.veredicto_llm}`));
    r.sev.append(h("span", { class: `sv ${res.severidad ?? "nada"}` }, res.severidad ?? "—"));
    r.dec.append(h("span", { class: `tg ${res.decision}` }, DECISION[res.decision] ?? "—"));
    r.conf.textContent = res.confianza != null ? Number(res.confianza).toFixed(2) : "";
    r.seg.textContent = res.segundos != null ? `${Math.round(res.segundos)} s` : "";
    if (res.correccion) r.ver.append(h("span", { class: "m", style: { fontSize: "11px", color: "var(--lime)" }, title: `${res.correccion.por}: ${res.correccion.motivo}` }, `Persona: ${res.correccion.veredicto}`));
  } else if (enCurso) {
    r.ver.append(h("span", { class: "m", style: { fontSize: "12px", color: "var(--mu)" } }, `${ETAPA[f.etapa].toLowerCase()}…`));
    r.sev.append(h("span", { class: "skel", style: { width: "70px" } }));
    r.dec.append(h("span", { class: "tg run" }, ETAPA[f.etapa]));
    r.conf.append(h("span", { class: "skel", style: { width: "30px" } }));
  } else if (f.etapa === "error") {
    r.dec.append(h("span", { class: "tg escalar" }, "Error"));
  } else {
    r.dec.append(h("span", { class: "tg" }, "En cola"));
  }
}

export function montarCola(raiz) {
  const filas = new Map();
  const cifras = {};
  const cifra = (clave, rotulo, color) =>
    h("div", { class: "cifra" }, cifras[clave] = h("b", { style: color ? { color } : {} }, "0"), h("span", {}, rotulo));
  let subtitulo, btnTriar, cuerpo;
  const selectores = {};

  function selector(clave, rotulo, opciones) {
    const caja = selectores[clave] = h("select", { "aria-label": rotulo, onChange: () => { filtros[clave] = caja.value; pintar(); } },
      h("option", { value: "" }, `${rotulo}: todas`), ...opciones.map(([valor, texto]) => h("option", { value: valor }, texto)));
    caja.value = filtros[clave];
    return caja;
  }
  let reglasPintadas = "";
  function opcionesDeRegla(lista) {
    const reglas = [...new Set(lista.map((f) => f.meta?.rule_id).filter(Boolean))].sort();
    if (reglas.join() === reglasPintadas) return;
    reglasPintadas = reglas.join();
    selectores.regla.replaceChildren(h("option", { value: "" }, "Regla: todas"), ...reglas.map((x) => h("option", { value: x }, x)));
    selectores.regla.value = reglas.includes(filtros.regla) ? filtros.regla : "";
    filtros.regla = selectores.regla.value;
  }

  raiz.replaceChildren(
    h("section", { class: "cabecera entra" },
      h("div", {}, h("h1", { class: "d" }, "Cola de alertas"), subtitulo = h("p")),
      h("div", { class: "cifras" },
        cifra("escalar", "escaladas", "#ff8f8f"), cifra("revisar", "a revisar", "var(--med)"),
        cifra("cerrar", "cerradas"), cifra("tiempo", "tiempo"),
        h("button", { class: "btn", type: "button", onClick: () => abrirPanel() }, "Cargar alertas"),
        btnTriar = h("button", { class: "btn go", type: "button" }))),
    h("section", { class: "filtros entra", "aria-label": "Filtros de la cola" },
      selector("regla", "Regla", []),
      selector("severidad", "Severidad", SEVERIDADES.slice().reverse().map((x) => [x, x])),
      selector("veredicto", "Veredicto", VEREDICTOS.map((x) => [x, x])),
      selector("estado", "Estado", ESTADOS),
      h("button", { class: "btn sm", type: "button", onClick: () => { Object.keys(filtros).forEach((k) => { filtros[k] = ""; selectores[k].value = ""; }); pintar(); } }, "Quitar filtros")),
    h("section", { class: "card scroll entra", role: "table", "aria-label": "Cola de alertas", style: { animationDelay: ".1s" } },
      h("div", { class: "fila hd", role: "row" },
        h("span"), h("span", { role: "columnheader" }, "Alerta"), h("span", { role: "columnheader" }, "Qué ha saltado"),
        h("span", { class: "pph", role: "columnheader" },
          h("span", { style: { color: "var(--co)" } }, "Evid."), h("span", { style: { color: "var(--ia)" } }, "IA"),
          h("span", { style: { color: "var(--co)" } }, "Polít."), h("span", { style: { color: "var(--lime)" } }, "Pers.")),
        h("span", { role: "columnheader" }, "Veredicto"), h("span", { role: "columnheader" }, "Severidad"),
        h("span", { role: "columnheader" }, "Decisión"), h("span", { role: "columnheader" }, "Conf."), h("span", { role: "columnheader" }, "Seg.")),
      cuerpo = h("div")),
    h("section", { class: "limites", "aria-label": "Límites" },
      h("span", { class: "chip", style: { color: "var(--tx)" } }, "Lo que no resuelve"),
      h("span", {}, "Acierto del 85 % en 42 casos etiquetados por nosotros"),
      h("span", {}, "Agrupa solo las alertas triadas de la cola, no busca otras en el dataset"),
      h("span", {}, "Desconocido no es limpio: baja la confianza"),
      h("span", {}, "Depende del servidor compartido del DCC"),
      h("button", { class: "btn sm", type: "button", style: { marginLeft: "auto" }, onClick: () => restablecerCola() }, "Restablecer las 10")));

  btnTriar.addEventListener("click", () => triarFilas([...estado.filas.keys()], estado.servidor?.paralelo ?? 5));

  function pintar() {
    const lista = [...estado.filas.values()];
    for (const f of lista) {
      if (!filas.has(f.id)) filas.set(f.id, crearFila(f.id));
    }
    for (const [id, el] of filas) {
      if (!estado.filas.has(id)) { el.remove(); filas.delete(id); }
    }
    opcionesDeRegla(lista);
    const visibles = lista.filter(pasaFiltros);
    for (const f of lista) if (!visibles.includes(f)) filas.get(f.id).remove();
    cuerpo.querySelectorAll(".vacio").forEach((e) => e.remove());
    // Primero lo que necesita a una persona; después lo cerrado; lo pendiente al final.
    const peso = (f) => (f.etapa === "listo" ? ({ escalar: 0, revisar: 1, cerrar: 3 }[f.resumen.decision] ?? 3) : f.etapa === "error" ? 2 : 4);
    const orden = visibles.map((f, i) => [f, i]).sort((a, b) => peso(a[0]) - peso(b[0]) || a[1] - b[1]).map(([f]) => f);
    orden.forEach((f, i) => {
      const el = filas.get(f.id);
      actualizarFila(el, f);
      if (cuerpo.children[i] !== el) cuerpo.insertBefore(el, cuerpo.children[i] ?? null);
    });
    if (!lista.length) cuerpo.replaceChildren(h("div", { class: "vacio" }, "No hay alertas en la cola. Pulsa «Cargar alertas»."));
    else if (!visibles.length) cuerpo.replaceChildren(h("div", { class: "vacio" }, "Ninguna alerta cumple los filtros."));

    const listas = lista.filter((f) => f.etapa === "listo");
    const cuenta = (d) => listas.filter((f) => f.resumen.decision === d).length;
    cifras.escalar.textContent = cuenta("escalar");
    cifras.revisar.textContent = cuenta("revisar");
    cifras.cerrar.textContent = cuenta("cerrar");
    cifras.tiempo.textContent = estado.triando || estado.segundos ? minutos(estado.segundos) : "—";
    const nGrupos = new Set([...estado.grupos.values()].map((x) => x.grupo_id)).size;
    subtitulo.textContent = `${visibles.length === lista.length ? "" : `${visibles.length} de ${lista.length} a la vista · `}${listas.length} de ${lista.length} triadas · ${estado.servidor?.paralelo ?? 5} a la vez${nGrupos ? ` · ${nGrupos} ataque${nGrupos === 1 ? "" : "s"} agrupado${nGrupos === 1 ? "" : "s"}` : ""}${estado.demo ? " · modo demo" : ""}`;
    btnTriar.textContent = estado.triando ? "Triando…" : `Triar las ${lista.length}`;
    btnTriar.disabled = estado.triando || !lista.length;
  }

  const baja = suscribir(pintar);
  pintar();
  return () => baja();
}
