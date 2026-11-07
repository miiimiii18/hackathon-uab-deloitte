import { api } from "./api.js";
import { h, icono } from "./dom.js";
import { añadirAlertas, estado, triarFilas } from "./estado.js";
import { aviso } from "./util.js";

const CAMPOS = ["alert_id", "rule_id", "severity", "created_at", "entities"];
const vacio = (v) => v == null || v === "" || (typeof v === "object" && Object.keys(v).length === 0);

// Acepta un objeto, una lista JSON o JSONL (una alerta por línea).
export function parsearAlertas(texto) {
  const t = texto.trim();
  if (!t) return { items: [], errores: [] };
  let lista;
  const errores = [];
  try {
    const v = JSON.parse(t);
    lista = Array.isArray(v) ? v : [v];
  } catch {
    lista = [];
    t.split(/\r?\n/).forEach((linea, i) => {
      if (!linea.trim()) return;
      try { lista.push(JSON.parse(linea)); } catch { errores.push(`Línea ${i + 1}: no es JSON válido`); }
    });
    if (!lista.length && !errores.length) errores.push("No es JSON válido");
  }
  const items = lista.map((alerta) => ({
    alerta,
    faltan: alerta && typeof alerta === "object" && !Array.isArray(alerta) ? CAMPOS.filter((c) => vacio(alerta[c])) : CAMPOS,
  }));
  return { items, errores };
}

let cerrarActual = null;

export function abrirPanel() {
  if (cerrarActual) return;
  const capa = document.getElementById("capa");
  let modo = "json";
  let validas = []; // alertas pegadas o subidas, ya validadas
  let marcadas = new Set(); // IDs del dataset elegidos
  const cuerpo = h("div", { style: { display: "flex", flexDirection: "column", gap: "16px" } });
  const resumen = h("div", { class: "val", "aria-label": "Validación" });
  const pie = h("div", { class: "pie-panel" });
  let area, buscador, lista;

  const cerrar = () => { capa.replaceChildren(); document.removeEventListener("keydown", alTeclear); cerrarActual = null; };
  const alTeclear = (e) => { if (e.key === "Escape") cerrar(); };
  document.addEventListener("keydown", alTeclear);
  cerrarActual = cerrar;

  function mostrarValidacion({ items, errores }) {
    validas = items.filter((i) => i.faltan.length === 0).map((i) => i.alerta);
    resumen.replaceChildren(
      ...errores.map((e) => h("span", { class: "mal" }, e)),
      ...items.flatMap((i, n) => (i.faltan.length
        ? [h("span", { class: "mal" }, `${i.alerta?.alert_id ?? `Alerta ${n + 1}`}: faltan ${i.faltan.join(", ")}`)]
        : [h("span", {}, `${i.alerta.alert_id} ✓`)])),
    );
    if (items.length === 1 && items[0].faltan.length === 0) {
      resumen.replaceChildren(...CAMPOS.map((c) => h("span", {}, `${c} ✓`)), ...errores.map((e) => h("span", { class: "mal" }, e)));
    }
    pintarPie();
  }

  function pintarPie() {
    const n = modo === "dataset" ? marcadas.size : validas.length;
    pie.replaceChildren(
      h("div", { style: { display: "flex", justifyContent: "space-between", color: "var(--mu)", fontSize: "13px", gap: "10px", flexWrap: "wrap" } },
        h("span", {}, `${n} alerta${n === 1 ? "" : "s"} lista${n === 1 ? "" : "s"}`), h("span", {}, "Unos 20 s por alerta, 5 a la vez")),
      h("div", { class: "fila-btn" },
        h("button", { class: "btn", type: "button", disabled: n === 0, onClick: () => añadir(false) }, "Solo añadir a la cola"),
        h("button", { class: "btn go", type: "button", disabled: n === 0 || estado.triando, onClick: () => añadir(true) }, "Añadir y triar")),
    );
  }

  async function añadir(triar) {
    const ids = modo === "dataset" ? await añadirAlertas({ ids: [...marcadas] })
      : await añadirAlertas({ objetos: validas });
    cerrar();
    if (triar) triarFilas(ids, estado.servidor?.paralelo ?? 5);
    else aviso(`${ids.length} alerta${ids.length === 1 ? "" : "s"} en la cola`, "ok");
  }

  async function leerFicheros(ficheros) {
    const textos = await Promise.all([...ficheros].map((f) => f.text()));
    mostrarValidacion(parsearAlertas(textos.join("\n")));
  }

  function pintarModo() {
    pestañas.forEach(([clave, boton]) => boton.classList.toggle("on", clave === modo));
    validas = [];
    marcadas = new Set();
    resumen.replaceChildren();
    if (modo === "json") {
      area = h("textarea", { "aria-label": "JSON de la alerta", placeholder: '{ "alert_id": "...", "rule_id": "...", "severity": "...", "created_at": "...", "entities": { } }', spellcheck: "false",
        onInput: () => mostrarValidacion(parsearAlertas(area.value)) });
      cuerpo.replaceChildren(area, resumen);
    } else if (modo === "ficheros") {
      const entrada = h("input", { type: "file", multiple: true, accept: ".json,.jsonl", hidden: true, onChange: () => leerFicheros(entrada.files) });
      const zona = h("div", { class: "soltar" },
        icono("subir", 26), h("span", {}, "Suelta aquí las alertas (.json o .jsonl)"),
        h("button", { class: "btn", type: "button", onClick: () => entrada.click() }, "Elegir archivos"), entrada);
      zona.addEventListener("dragover", (e) => { e.preventDefault(); zona.classList.add("sobre"); });
      zona.addEventListener("dragleave", () => zona.classList.remove("sobre"));
      zona.addEventListener("drop", (e) => { e.preventDefault(); zona.classList.remove("sobre"); leerFicheros(e.dataTransfer.files); });
      cuerpo.replaceChildren(zona, resumen);
    } else {
      buscador = h("input", { type: "search", placeholder: "Buscar por ID, regla o producto (muestra de 150)", "aria-label": "Buscar alerta",
        style: { minHeight: "44px", padding: "0 14px", borderRadius: "12px", border: "1px solid #3a444a", background: "#0a0e10", color: "var(--tx)", font: "14px var(--f-b)" } });
      lista = h("div", { class: "lista-ds" });
      let espera;
      buscador.addEventListener("input", () => { clearTimeout(espera); espera = setTimeout(buscar, 250); });
      cuerpo.replaceChildren(buscador, lista);
      buscar();
    }
    pintarPie();
  }

  async function buscar() {
    const encontradas = await api.buscar(buscador.value).catch((e) => { aviso(e.message); return []; });
    lista.replaceChildren(...encontradas.map((a) => {
      const caja = h("input", { type: "checkbox", checked: marcadas.has(a.alert_id) || estado.filas.has(a.alert_id), disabled: estado.filas.has(a.alert_id),
        onChange: () => { caja.checked ? marcadas.add(a.alert_id) : marcadas.delete(a.alert_id); pintarPie(); } });
      return h("label", {}, caja,
        h("span", { class: "m", style: { fontSize: "12px", color: "var(--mu)" } }, a.alert_id),
        h("span", { style: { flex: 1 } }, a.rule_name ?? a.rule_id), h("span", { class: `sv ${a.severity}` }, a.severity));
    }));
    if (!encontradas.length) lista.replaceChildren(h("div", { class: "vacio" }, "Sin resultados"));
  }

  const pestañas = [["json", "Pegar JSON"], ["ficheros", "Subir archivos"], ["dataset", "Del dataset"]].map(([clave, texto]) =>
    [clave, h("button", { class: "tab", type: "button", onClick: () => { modo = clave; pintarModo(); } }, texto)]);

  const cierre = h("button", { class: "btn sm", type: "button", onClick: cerrar }, "Cerrar");
  capa.replaceChildren(
    h("div", { class: "velo", onClick: cerrar }),
    h("aside", { class: "panel", role: "dialog", "aria-modal": "true", "aria-label": "Cargar alertas" },
      h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px" } }, h("h2", { class: "d" }, "Cargar alertas"), cierre),
      h("p", { style: { margin: "-6px 0 0", color: "var(--mu)" } }, "Pueden ser alertas que el sistema no haya visto."),
      h("div", { class: "tabs" }, ...pestañas.map(([, b]) => b)),
      cuerpo, pie));
  pintarModo();
  cierre.focus();
}
