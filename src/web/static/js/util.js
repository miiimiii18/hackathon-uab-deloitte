export const DECISION = { escalar: "Escalar a N2", revisar: "Revisar", cerrar: "Cerrar" };
export const SEVERIDADES = ["informational", "low", "medium", "high", "critical"];

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
