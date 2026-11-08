export const DECISION = { escalar: "Escalar a N2", revisar: "Revisar", cerrar: "Cerrar" };
export const SELLO = { escalar: "Escalar · N2", revisar: "Revisión humana", cerrar: "Cerrar" };
export const SEVERIDADES = ["informational", "low", "medium", "high", "critical"];
// Lo que se lee en pantalla; los valores internos (los del esquema de Deloitte) no cambian.
export const VEREDICTO = { true_positive: "Ataque real", benign_true_positive: "Autorizado", false_positive: "Falsa alarma", needs_more_info: "Falta información" };
export const GRAVEDAD = { informational: "info", low: "baja", medium: "media", high: "alta", critical: "crítica" };
export const veredicto = (v) => VEREDICTO[v] ?? v ?? "—";
export const gravedad = (s) => GRAVEDAD[s] ?? s ?? "—";
// Los textos de la política mezclan valores internos («true_positive de severidad critical»): se leen en castellano.
const TERMINOS = new RegExp(`\\b(${[...Object.keys(VEREDICTO), ...Object.keys(GRAVEDAD)].join("|")})\\b`, "g");
export const legible = (texto) => String(texto ?? "").replace(TERMINOS, (t) => (VEREDICTO[t] ?? GRAVEDAD[t]).toLowerCase()).replace(/\bseveridad\b/g, "gravedad");

export const ETAPA = {
  pendiente: "En cola",
  evidencia: "Evidencia",
  ia: "IA analiza",
  politica: "Política",
};

export function hora(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso || "";
  return d.toLocaleString("es-ES", { timeZone: "Europe/Madrid", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function minutos(segundos) {
  const s = Math.max(0, Math.floor(segundos));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

export const siNo = (v) => (String(v).toLowerCase() === "true" ? "Sí" : "No");

export function cortar(texto, max = 70) {
  const t = String(texto ?? "");
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export function descargar(nombre, objeto) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(objeto, null, 2)], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: nombre });
  a.click();
  URL.revokeObjectURL(url);
}

export function aviso(texto, tipo = "error") {
  const caja = document.getElementById("avisos");
  const el = document.createElement("div");
  el.className = `aviso-toast ${tipo === "ok" ? "ok" : ""}`;
  el.textContent = texto;
  caja.append(el);
  setTimeout(() => el.remove(), tipo === "ok" ? 3500 : 8000);
}
