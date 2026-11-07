// Helpers para construir el DOM. Todo el texto entra como texto (nunca como HTML):
// lo que viene de alertas y logs lo puede escribir el atacante.
const SVG_NS = "http://www.w3.org/2000/svg";

export function añadir(el, hijos) {
  for (const c of hijos.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function h(tag, props = {}, ...hijos) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  return añadir(el, hijos);
}

export function svg(tag, attrs = {}, ...hijos) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  for (const c of hijos.flat()) if (c) el.append(c);
  return el;
}

const ICONOS = {
  flecha: [["path", { d: "M5 12h14M13 6l6 6-6 6" }]],
  atras: [["path", { d: "M19 12H5M11 6l-6 6 6 6" }]],
  check: [["path", { d: "M5 12l5 5L20 7" }]],
  subir: [["path", { d: "M12 16V4M7 9l5-5 5 5M5 20h14" }]],
  play: [["path", { d: "M7 4l13 8-13 8z", fill: "currentColor", stroke: "none" }]],
};

export function icono(nombre, tam = 18, grosor = 2.4) {
  return svg("svg", { width: tam, height: tam, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
    "stroke-width": grosor, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" },
  ...ICONOS[nombre].map(([t, a]) => svg(t, a)));
}

export function logo(tam = 34) {
  return svg("svg", { width: tam, height: tam, viewBox: "0 0 34 34", "aria-hidden": "true" },
    svg("rect", { x: 1, y: 1, width: 32, height: 32, rx: 10, fill: "#151b1e", stroke: "#222b2f" }),
    svg("circle", { cx: 17, cy: 17, r: 8, fill: "none", stroke: "#b4f04a", "stroke-width": 2.4 }),
    svg("circle", { cx: 17, cy: 17, r: 2.6, fill: "#b4f04a" }));
}

export function anilloConfianza(confianza, tam = 84) {
  const c = Math.max(0, Math.min(1, Number(confianza) || 0));
  return svg("svg", { class: "anillo", width: tam, height: tam, viewBox: "0 0 80 80", role: "img", "aria-label": `Confianza ${c.toFixed(2)}` },
    svg("circle", { cx: 40, cy: 40, r: 34, fill: "none", stroke: "#2a2547", "stroke-width": 7 }),
    svg("circle", { cx: 40, cy: 40, r: 34, fill: "none", stroke: "#bba6ff", "stroke-width": 7, "stroke-linecap": "round",
      "stroke-dasharray": 214, transform: "rotate(-90 40 40)",
      style: `stroke-dashoffset:${(214 * (1 - c)).toFixed(1)};animation:anillo 1.6s cubic-bezier(.2,.7,.2,1) .3s both` }),
    (() => {
      const t = svg("text", { x: 40, y: 45, "text-anchor": "middle", "font-family": "var(--f-m)", "font-size": 16, fill: "#f2f5f3" });
      t.textContent = c.toFixed(2);
      return t;
    })());
}
