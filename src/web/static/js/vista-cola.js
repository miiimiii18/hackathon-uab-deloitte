import { añadir, h } from "./dom.js";
import { abrirPanel } from "./panel.js";
import { estado, suscribir, triarFilas, vaciarBandeja } from "./estado.js";
import { cortar, ETAPA, gravedad, legible, minutos, SELLO, SEVERIDADES, veredicto, VEREDICTO } from "./util.js";

// La cola como un «libro» de alertas: cada fila dice qué ha pasado, por qué (con su cita), qué
// propone la IA, qué decide el código y el sello de la decisión. Lo calcula todo el servidor.

const ESTADOS = [["escalar", "Escalar a N2"], ["revisar", "Revisión humana"], ["cerrar", "Cerrar"], ["pendiente", "Sin triar"], ["error", "Con error"]];
// Fuera de la vista para que sigan al volver desde el detalle, y en sessionStorage para que sigan tras F5.
// No en localStorage: un filtro olvidado ocultaría alertas en la siguiente demo.
const CLAVE_FILTROS = "temipo.filtros";
const filtros = { regla: "", severidad: "", veredicto: "", estado: "", ...JSON.parse(sessionStorage.getItem(CLAVE_FILTROS) ?? "{}") };
const guardarFiltros = () => sessionStorage.setItem(CLAVE_FILTROS, JSON.stringify(filtros));

// Una alerta que forma parte de un ataque agrupado sube a N2 con su grupo (el servidor escala todo
// grupo), aunque por sí sola se cerraría. Se enseña así para que «Ataque real» + «Cerrar» no confunda.
const subePorGrupo = (f) => f.etapa === "listo" && f.resumen.decision !== "escalar" && estado.grupos.get(f.id)?.ticket?.decision === "escalar";
const decisionDe = (f) => (subePorGrupo(f) ? "escalar" : f.resumen.decision);

function pasaFiltros(f) {
  const listo = f.etapa === "listo";
  const r = f.resumen;
  if (filtros.regla && f.meta?.rule_id !== filtros.regla) return false;
  if (filtros.severidad && !(listo && r.severidad === filtros.severidad)) return false;
  if (filtros.veredicto && !(listo && r.veredicto === filtros.veredicto)) return false;
  if (filtros.estado) {
    const actual = listo ? decisionDe(f) : f.etapa === "error" ? "error" : "pendiente";
    if (actual !== filtros.estado) return false;
  }
  return true;
}

// Barra de etapas mientras se tría: evidencia → IA → política.
const ETAPAS = { pendiente: ["", "", ""], evidencia: ["a", "", ""], ia: ["d", "a", ""], politica: ["d", "d", "a"], error: ["x", "x", "x"] };

// Un punto por consulta: rojo = malicioso, hueco = desconocido (no es limpio), verde = limpio, gris = el resto.
function puntos(c) {
  const total = Math.min(c?.total ?? 0, 60);
  const m = c?.malicioso ?? 0, u = c?.desconocido ?? 0, l = c?.limpio ?? 0;
  return h("div", { class: "puntos", "aria-hidden": "true" },
    ...Array.from({ length: total }, (_, i) => h("i", { class: i < m ? "m" : i < m + u ? "u" : i < m + u + l ? "c" : "" })));
}

function ajuste(n) {
  const v = Number(n) || 0;
  return v > 0 ? ` +${v}` : v < 0 ? ` −${-v}` : "";
}

function cuentaGravedad(r) {
  const final = h("span", { class: `sv ${r.severidad ?? "nada"}` }, gravedad(r.severidad));
  if (["false_positive", "benign_true_positive"].includes(r.veredicto)) return [h("span", { class: "m" }, `${veredicto(r.veredicto).toLowerCase()} → `), final];
  if (!r.severidad_regla) return [final];
  return [h("span", { class: "m" }, `${gravedad(r.severidad_regla)} × ${String(r.criticidad ?? "?").toLowerCase()}${ajuste(r.ajuste)} → `), final];
}

function crearFila(id) {
  const r = {};
  const el = h("a", { class: "fila", href: `#/alerta/${encodeURIComponent(id)}`, role: "row" },
    r.num = h("span", { class: "num", role: "cell" }),
    h("div", { role: "cell", style: { minWidth: 0 } }, r.tit = h("div", { class: "tit" }), r.sub = h("div", { class: "sub" }), r.razon = h("div"), r.extra = h("div")),
    r.cadena = h("div", { class: "cadena", role: "cell" }),
    r.cons = h("div", { role: "cell" }),
    r.sello = h("div", { class: "sello-c", role: "cell" }));
  el.refs = r;
  return el;
}

function actualizarFila(el, f, n) {
  const r = el.refs;
  const res = f.resumen;
  const listo = f.etapa === "listo";
  const enCurso = ["evidencia", "ia", "politica"].includes(f.etapa);

  r.num.textContent = String(n).padStart(2, "0");
  r.tit.textContent = res?.titulo ?? f.meta?.rule_name ?? f.id;
  r.sub.replaceChildren(h("span", {}, [f.id, f.meta?.source_product, f.meta?.rule_id].filter(Boolean).join(" · ")));
  const g = estado.grupos.get(f.id);
  if (g && listo) r.sub.append(h("span", { class: "chip c-med", title: `Mismo ataque: ${g.alert_ids.join(", ")}` }, `Mismo ataque · ${g.alert_ids.length} alertas`));
  if (res?.duplicada_de && listo) r.sub.append(h("span", { class: "chip", title: "Misma regla, entidades y evidencia: no se vuelve a triar" }, `Duplicada de ${res.duplicada_de}`));

  r.razon.replaceChildren();
  r.extra.replaceChildren();
  r.cadena.replaceChildren();
  r.cons.replaceChildren();
  r.sello.replaceChildren();

  if (f.error) r.razon.append(h("div", { class: "err" }, f.error));
  if (listo) {
    if (res.razon_ia?.texto) {
      r.razon.className = "razon";
      añadir(r.razon, [h("span", { class: "ia-marca" }, "✦ "), h("span", { class: "ia-voz" }, res.razon_ia.texto), " ", res.razon_ia.cita && res.razon_ia.cita !== f.id ? h("span", { class: "cita" }, res.razon_ia.cita) : null]); // citar la propia alerta no aporta
    }
    if (res.razon_codigo) r.extra.append(h("div", { class: "razon-co", title: legible(res.razon_codigo) }, `{ } ${cortar(legible(res.razon_codigo), 170)}`));
    const corrige = res.veredicto_llm && res.veredicto_llm !== res.veredicto;
    añadir(r.cadena, [
      h("div", { class: "p" }, h("span", { class: "cap" }, "✦ IA"),
        h("span", {}, h("span", { class: "ia-voz", style: { fontSize: "14px" } }, veredicto(res.veredicto_llm ?? res.veredicto)), " ",
          h("span", { class: "m", style: { color: "var(--mu)" } }, res.confianza != null ? Number(res.confianza).toFixed(2).replace(".", ",") : ""))),
      h("div", { class: "p" }, h("span", { class: "cap" }, "{ } Código"),
        h("span", {}, corrige ? h("b", { style: { color: "var(--med)" } }, `corrige: ${veredicto(res.veredicto)} · `) : null, ...cuentaGravedad(res))),
      res.correccion ? h("div", { class: "p" }, h("span", { class: "cap", style: { color: "var(--lime)" } }, "✍ Persona"),
        h("span", { style: { color: "var(--lime)" }, title: `${res.correccion.por}: ${res.correccion.motivo}` }, `corrige: ${veredicto(res.correccion.veredicto)}`)) : null]);
    r.cons.append(h("div", { class: "cap" }, `${res.consultas?.total ?? "?"} consultas`), puntos(res.consultas),
      res.segundos != null ? h("div", { class: "m", style: { fontSize: "11px", color: "var(--mu)", marginTop: "4px" } }, `${Math.round(res.segundos)} s`) : null);
    if (subePorGrupo(f)) {
      r.sello.append(h("span", { class: "sello escalar", title: `Sola se ${res.decision === "cerrar" ? "cerraría" : "revisaría"}; su grupo (mismo ataque) se escala a N2` }, "Escalar · grupo"));
    } else {
      r.sello.append(h("span", { class: `sello ${res.decision}` }, SELLO[res.decision] ?? res.decision));
    }
  } else if (enCurso) {
    r.razon.className = "razon";
    r.razon.append(h("span", { class: "ia-voz", style: { color: "var(--mu)" } }, `${ETAPA[f.etapa]}…`));
    r.cadena.append(h("span", { class: "skel", style: { width: "160px" } }), h("span", { class: "skel", style: { width: "120px" } }));
    r.cons.append(h("div", { class: "cap" }, ETAPA[f.etapa]), h("div", { class: "etapas" }, ...ETAPAS[f.etapa].map((c) => h("i", { class: c }))));
    r.sello.append(h("span", { class: "sello run" }, "Triando"));
  } else if (f.etapa === "error") {
    r.sello.append(h("span", { class: "sello error" }, "Error"));
  } else {
    r.sello.append(h("span", { class: "sello cola" }, "En la bandeja"));
  }
}

export function montarCola(raiz) {
  const filas = new Map();
  const cifras = {};
  const cifra = (clave, rotulo, color) => h("div", {}, h("span", { class: "cap" }, rotulo), cifras[clave] = h("b", { style: color ? { color } : {} }, "0"));
  let titular, entradilla, btnTriar, btnVaciar, cuerpo, resumenTiempo;
  const selectores = {};

  function selector(clave, rotulo, opciones) {
    const caja = selectores[clave] = h("select", { "aria-label": rotulo, onChange: () => { filtros[clave] = caja.value; guardarFiltros(); pintar(); } },
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
    guardarFiltros();
  }

  raiz.replaceChildren(
    h("section", { class: "bandeja entra" },
      h("div", {}, h("div", { class: "cap" }, "Bandeja de entrada"), titular = h("h1"), entradilla = h("p")),
      h("div", { class: "drop" },
        h("div", { class: "pila", "aria-hidden": "true" }, h("b"), h("b"), h("b"), h("b")),
        h("div", { style: { flex: "1 1 160px" } }, h("b", { style: { fontWeight: 600 } }, "Alertas nuevas"),
          h("div", { class: "m", style: { fontSize: "12px", color: "var(--mu)" } }, "JSON o JSONL")),
        btnVaciar = h("button", { class: "btn", type: "button", title: "Quita todas las alertas de la bandeja",
          onClick: () => { if (confirm("¿Vaciar la bandeja? Se quitan todas las alertas de la lista (los resultados guardados no se borran).")) vaciarBandeja(); } }, "Vaciar"),
        h("button", { class: "btn", type: "button", onClick: () => abrirPanel() }, "Cargar alertas"),
        btnTriar = h("button", { class: "btn go", type: "button" }))),
    h("section", { class: "marcador entra", "aria-label": "Resumen" },
      h("div", {}, h("span", { class: "cap" }, "Triadas"), h("b", {}, cifras.listas = h("span", {}, "0"), resumenTiempo = h("small"))),
      cifra("escalar", "Escalar a N2", "var(--crit)"), cifra("revisar", "Revisión humana", "var(--med)"),
      cifra("cerrar", "Cerrar", "var(--ok)"), cifra("grupos", "Ataques agrupados")),
    h("div", { class: "sec" }, h("h2", {}, "Las alertas, una por una"), h("span", { class: "nivel" }, "N1"), h("span", { class: "nivel" }, "N2"),
      h("span", { class: "nota-d leyenda-p" },
        h("i", { style: { background: "var(--crit)" } }), "maliciosa", h("i", { style: { boxShadow: "inset 0 0 0 1.3px var(--med)" } }), "desconocida",
        h("i", { style: { background: "var(--ok)" } }), "limpia")),
    h("section", { class: "filtros", "aria-label": "Filtros" },
      selector("regla", "Regla", []),
      selector("severidad", "Gravedad", SEVERIDADES.slice().reverse().map((x) => [x, gravedad(x)])),
      selector("veredicto", "Veredicto", Object.entries(VEREDICTO)),
      selector("estado", "Decisión", ESTADOS),
      h("button", { class: "btn sm", type: "button", onClick: () => { Object.keys(filtros).forEach((k) => { filtros[k] = ""; selectores[k].value = ""; }); guardarFiltros(); pintar(); } }, "Quitar filtros")),
    cuerpo = h("section", { class: "libro", role: "table", "aria-label": "Alertas" }),
    h("div", { class: "sec" }, h("h2", {}, "Lo que este parte no garantiza")),
    h("section", { class: "limites", "aria-label": "Límites" },
      h("div", {}, h("b", {}, "80–86 %"), h("h3", {}, "de veredictos acertados")),
      h("div", {}, h("b", {}, "2–6"), h("h3", {}, "casos cambian entre repeticiones")),
      h("div", {}, h("b", {}, "○"), h("h3", {}, "desconocido no es limpio")),
      h("div", {}, h("b", {}, "±24 h"), h("h3", {}, "de contexto por alerta"))));

  btnTriar.addEventListener("click", () => triarFilas([...estado.filas.keys()], estado.servidor?.paralelo ?? 5));

  function pintar() {
    const lista = [...estado.filas.values()];
    for (const f of lista) if (!filas.has(f.id)) filas.set(f.id, crearFila(f.id));
    for (const [id, el] of filas) if (!estado.filas.has(id)) { el.remove(); filas.delete(id); }
    opcionesDeRegla(lista);
    const visibles = lista.filter(pasaFiltros);
    for (const f of lista) if (!visibles.includes(f)) filas.get(f.id).remove();
    cuerpo.querySelectorAll(".vacio").forEach((e) => e.remove());
    // Primero lo que necesita a una persona; después lo cerrado; lo pendiente al final.
    const peso = (f) => (f.etapa === "listo" ? ({ escalar: 0, revisar: 1, cerrar: 3 }[decisionDe(f)] ?? 3) : f.etapa === "error" ? 2 : 4);
    const orden = visibles.map((f, i) => [f, i]).sort((a, b) => peso(a[0]) - peso(b[0]) || a[1] - b[1]).map(([f]) => f);
    orden.forEach((f, i) => {
      const el = filas.get(f.id);
      actualizarFila(el, f, i + 1);
      if (cuerpo.children[i] !== el) cuerpo.insertBefore(el, cuerpo.children[i] ?? null);
    });
    if (!lista.length) cuerpo.replaceChildren(h("div", { class: "vacio" }, "Carga el JSON con las alertas para empezar."));
    else if (!visibles.length) cuerpo.replaceChildren(h("div", { class: "vacio" }, "Ninguna alerta cumple los filtros."));

    const listas = lista.filter((f) => f.etapa === "listo");
    const cuenta = (d) => listas.filter((f) => decisionDe(f) === d).length;
    cifras.listas.textContent = `${listas.length}`;
    resumenTiempo.textContent = estado.triando || estado.segundos ? ` en ${minutos(estado.segundos)}` : ` de ${lista.length}`;
    cifras.escalar.textContent = cuenta("escalar");
    cifras.revisar.textContent = cuenta("revisar");
    cifras.cerrar.textContent = cuenta("cerrar");
    cifras.grupos.textContent = new Set([...estado.grupos].filter(([id]) => estado.filas.has(id)).map(([, x]) => x.grupo_id)).size;
    titular.textContent = estado.triando ? `Triando ${lista.length} alertas…` : lista.length ? `${lista.length} alerta${lista.length === 1 ? "" : "s"} en la bandeja.` : "La bandeja está vacía.";
    entradilla.textContent = visibles.length === lista.length ? "" : `A la vista: ${visibles.length} de ${lista.length}.`;
    btnTriar.textContent = estado.triando ? "Triando…" : lista.length ? `Triar las ${lista.length}` : "Triar";
    btnTriar.disabled = estado.triando || !lista.length;
    btnVaciar.hidden = !lista.length; // solo se ofrece cuando hay algo que quitar
    btnVaciar.disabled = estado.triando;
  }

  const baja = suscribir(pintar);
  pintar();
  return () => baja();
}
