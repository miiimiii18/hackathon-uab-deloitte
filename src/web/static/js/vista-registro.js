import { api } from "./api.js";
import { h } from "./dom.js";
import { aviso } from "./util.js";

// Lo que ha ejecutado la contención simulada (containment_log.jsonl de la API del SOC).
export function montarRegistro(raiz) {
  let vivo = true;
  const cuerpo = h("div");
  const recargar = async () => {
    cuerpo.replaceChildren(h("div", { class: "vacio" }, "Cargando…"));
    const filas = await api.registro().catch((e) => { aviso(e.message); return null; });
    if (!vivo) return;
    if (!filas) return cuerpo.replaceChildren(h("div", { class: "vacio" }, "No se pudo leer el registro. ¿Está arrancada la API del SOC?"));
    if (!filas.length) return cuerpo.replaceChildren(h("div", { class: "vacio" }, "Todavía no se ha ejecutado ninguna acción."));
    cuerpo.replaceChildren(
      h("div", { class: "tabla-reg hd", role: "row" }, ...["Cuándo", "Acción", "Objetivo", "Ticket", "Aprobación", "Resultado"].map((t) => h("span", { role: "columnheader" }, t))),
      ...[...filas].reverse().map((e) => h("div", { class: "tabla-reg", role: "row" },
        h("span", { class: "m", role: "cell" }, String(e.timestamp ?? "").replace("T", " ").slice(0, 19)),
        h("span", { class: "m", role: "cell" }, e.action),
        h("span", { class: "m", role: "cell" }, e.target),
        h("span", { class: "m", role: "cell" }, e.ticket_id || "—"),
        h("span", { class: "m", role: "cell" }, e.approval_token || "sin token (N1)"),
        h("span", { role: "cell" }, e.result))));
  };
  raiz.replaceChildren(
    h("section", { class: "cabecera entra" },
      h("div", {}, h("h1", { class: "d" }, "Registro de contención"),
        h("p", {}, "Acciones ejecutadas en la API simulada. Cada una necesitó la aprobación de una persona, salvo block_ioc y purge_email.")),
      h("div", { class: "cifras" }, h("a", { class: "btn", href: "#/" }, "Cola de alertas"), h("button", { class: "btn go", type: "button", onClick: recargar }, "Actualizar"))),
    h("section", { class: "card scroll entra", role: "table", "aria-label": "Registro de contención" }, cuerpo));
  recargar();
  return () => { vivo = false; };
}
