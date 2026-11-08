import { api } from "./api.js";
import { h } from "./dom.js";
import { estado, iniciar, ponerDemo, suscribir } from "./estado.js";
import { montarCola } from "./vista-cola.js";
import { montarDetalle } from "./vista-detalle.js";
import { montarRegistro } from "./vista-registro.js";
import { aviso } from "./util.js";

const cabecera = document.getElementById("cabecera");
const vista = document.getElementById("vista");
let desmontar = () => {};

const COMANDO_SOC = "uvicorn mock_soc_api:app --app-dir data/tarvia/06_herramientas --port 8000";

// Lo que impide triar de verdad, dicho con el arreglo. Con el modo demo activado no estorba.
function problemas(s) {
  if (s == null) return [["mal", "No hay conexión con el servidor de la web. Arráncalo con: python -m src.web"]];
  const lista = [];
  if (!s.soc) lista.push(["mal", `La API del SOC no responde en ${s.soc_url}. Arráncala en otra terminal: ${COMANDO_SOC}`]);
  if (s.llm_aviso) lista.push([s.llm ? "info" : "mal", s.llm_aviso]);
  return lista;
}

function pintarSistema() {
  const lista = problemas(estado.servidor);
  const bloquea = lista.some(([tipo]) => tipo === "mal") && !estado.demo;
  document.getElementById("sistema").replaceChildren(...lista.map(([tipo, texto]) =>
    h("div", { class: `sistema ${tipo}`, role: tipo === "mal" ? "alert" : "status" },
      h("span", {}, texto),
      tipo === "mal" && bloquea ? h("button", { class: "btn sm", type: "button", onClick: () => ponerDemo(true) }, "Usar modo demo") : null)));
}

function pintarCabecera() {
  const s = estado.servidor;
  const luz = (ok) => h("span", { class: `dot ${s == null ? "" : ok ? "ok" : "mal"}` });
  const hoy = new Date().toLocaleDateString("es-ES", { weekday: "long", day: "numeric", month: "long", year: "numeric" });
  cabecera.replaceChildren(
    h("div", { class: "fecha" }, hoy.charAt(0).toUpperCase() + hoy.slice(1), h("br"), "SOC de Tarvia Group · equipo TEMIPO"),
    h("a", { class: "marca", href: "#/", "aria-label": "Parte de triaje, volver a las alertas" }, h("b", {}, "Parte de triaje"), h("span", {}, "Nivel 1 asistido por IA · reto Deloitte")),
    h("div", { class: "estado" },
      h("span", { class: "chip", title: s?.soc_url }, luz(s?.soc), "API del SOC"),
      h("span", { class: "chip", title: s?.llm_aviso || (s ? `Modelo ${s.modelo}` : "") }, luz(s?.llm), s?.llm ? `${s.modelo} · DCC` : "LLM no disponible"),
      h("label", { class: "chip", title: "Reproduce resultados guardados, sin tocar la API ni el LLM" },
        h("input", { type: "checkbox", checked: estado.demo, onChange: (e) => ponerDemo(e.target.checked) }), "Modo demo")));
  pintarSistema();
}

async function refrescarServidor() {
  estado.servidor = await api.estado().catch(() => null);
  pintarCabecera();
}

function enrutar() {
  desmontar();
  const m = location.hash.match(/^#\/alerta\/(.+)$/);
  if (m) desmontar = montarDetalle(vista, decodeURIComponent(m[1]));
  else if (location.hash === "#/registro") desmontar = montarRegistro(vista);
  else desmontar = montarCola(vista);
  window.scrollTo(0, 0);
}

suscribir(() => {
  pintarSistema();
  const caja = cabecera.querySelector("input[type=checkbox]");
  if (caja && caja.checked !== estado.demo) caja.checked = estado.demo;
});

window.addEventListener("hashchange", enrutar);
pintarCabecera();
await refrescarServidor();
await iniciar().catch((e) => aviso(`No se pudo cargar la cola: ${e.message}`));
enrutar();
setInterval(refrescarServidor, 15000);
