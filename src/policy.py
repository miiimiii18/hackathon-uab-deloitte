"""Política del SOC de Tarvia en código (data/tarvia/01_contexto/politica_soc.md).

Lo que es una regla fija NO lo decide el LLM (ver «Principios de diseño» en CLAUDE.md):
1. Verificar el veredicto: `benign_true_positive` solo con una autorización citable.
2. Severidad final: matriz (severidad de la regla × criticidad afectada) y ajuste ±1.
3. Escalado obligatorio a N2 y SLA.
4. Permisos de contención: quién aprueba cada acción y qué no se puede hacer nunca (OT).

Cada decisión lleva su «porqué» en texto, para enseñarlo en la UI y defenderlo ante el jurado.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel

from src.evidencia import PATRON_CAMBIO
from src.llm import AnalisisLLM
from src.soc_client import a_fecha

SEVERIDADES = ["informational", "low", "medium", "high", "critical"]
CRITICIDADES = ["Baja", "Media", "Alta", "Crítica"]

# Sección 2 de la política: fila = severidad de la regla, columna = criticidad.
MATRIZ = {
    "informational": ["informational", "informational", "low", "low"],
    "low": ["informational", "low", "low", "medium"],
    "medium": ["low", "medium", "medium", "high"],
    "high": ["medium", "high", "high", "critical"],
    "critical": ["high", "critical", "critical", "critical"],
}

# Sección 3: SLA según la severidad final.
SLA = {
    "critical": {"tiempo_triaje": "15 min", "escalado": "Inmediato a N2 de guardia por teléfono", "notificar": "Responsable SOC y CISO"},
    "high": {"tiempo_triaje": "30 min", "escalado": "A N2 en la misma jornada", "notificar": "Responsable SOC"},
    "medium": {"tiempo_triaje": "4 h", "escalado": "A N2 si tras el triaje hay indicios de compromiso", "notificar": "—"},
    "low": {"tiempo_triaje": "24 h", "escalado": "No", "notificar": "—"},
    "informational": {"tiempo_triaje": "Revisión en lote diaria", "escalado": "No", "notificar": "—"},
}

# Cuando la alerta no apunta a un activo de la CMDB, la criticidad sale del servicio
# de negocio afectado (ficha de la empresa y servicios_negocio.csv).
CRITICIDAD_POR_PRODUCTO = {
    "WAF": ("Crítica", "Tienda online y app (frontales web)"),
    "ECOM": ("Crítica", "Tienda online y app"),
    "AI_GATEWAY": ("Alta", "Asistente de compra Vela"),
}

# Sección 5: reglas cuyo true_positive es fraude económico.
REGLAS_FRAUDE = {"UC-EML-004", "UC-WEB-003"}

# Autorizaciones. La principal es un cambio (CHG-...) o flujo (FLUJO-...) del calendario
# de cambios que aparezca en la evidencia y cuya ventana de fechas cubra la alerta: así
# se verifican el pentest (CHG-2026-1042), los escaneos de NESSUS01, las nóminas a la
# gestoría (FLUJO-0007)... con DATOS, no con palabras que un atacante podría escribir.
# (El patrón de los IDs, PATRON_CAMBIO, está en src/evidencia.py y se importa arriba.)
# IPs o rangos que un cambio permite como origen, p. ej. «IPs origen 192.0.2.10-12».
PATRON_IPS = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})(?:\s*-\s*(\d{1,3}))?\b")
# Horas del calendario: hora de España sin zona; en el periodo del dataset, UTC+2.
DESFASE_ESPANA = timedelta(hours=2)
TOLERANCIA = timedelta(hours=1)


def _en_horario_logisoft(momento: datetime | None) -> bool:
    """ext.logisoft: de lunes a viernes, de 8 a 18 h (hora de España)."""
    if momento is None:
        return False
    local = momento + DESFASE_ESPANA
    return local.weekday() < 5 and 8 <= local.hour < 18


# Reglas internas de empresa_tarvia.md que NO están en el calendario de cambios, con su
# comprobación (recibe la hora UTC de la alerta).
REGLAS_INTERNAS = {
    "svc_backup": ("svc_backup excluida de MFA (riesgo aceptado en 2024)", lambda m: True),
    "teamviewer": ("TeamViewer Corporate gestionado por IT (herramienta aprobada)", lambda m: True),
    "logisoft": ("Acceso de ext.logisoft a WMS01 (L–V, 8–18 h)", _en_horario_logisoft),
}

# Sección 4: servicios de uso dual que no se bloquean globalmente sin N2.
USO_DUAL = ("mega.nz", "mega.io", "anydesk")
TIPOS_OT = {"PLC", "HMI", "Estación de ingeniería"}
HOSTS_PERMITIDOS_OT = {"ENG-WS01", "WMS01"}
# Si el modelo dice benign_true_positive con menos confianza que esto y la autorización
# no se verifica, no se cierra como false_positive: revisión humana.
CONFIANZA_MINIMA = 0.7
TIPOS_NEGOCIO = {"TPV", "Frontal web", "Pasarela de pagos"}

Veredicto = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]


class AccionPolitica(BaseModel):
    action: str
    target: str
    justification: str
    requires_approval: bool
    aprobador: str  # quién la aprueba («—» si la ejecuta el N1)
    permitida: bool  # False = la política la prohíbe (p. ej., OT): solo escalar
    nota: str = ""


class DecisionPolitica(BaseModel):
    veredicto: Veredicto
    veredicto_llm: Veredicto
    autorizacion: str  # autorización verificada, o vacío
    criticidad: str
    origen_criticidad: str
    severidad_regla: str
    severidad_base: str
    ajuste: int  # -1, 0 o +1
    motivos_ajuste: list[str]
    severidad_final: str
    razon_severidad: str  # cómo se aplicó la matriz, en una frase (severity_rationale)
    decision: Literal["cerrar", "escalar", "revisar"]
    motivos_escalado: list[str]
    sla: dict[str, str]
    acciones: list[AccionPolitica]
    avisos: list[str]  # correcciones al LLM y cosas que debe mirar una persona


# --- Utilidades ---------------------------------------------------------------------


def _sin_acentos(texto: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", texto) if unicodedata.category(c) != "Mn").lower()


def normalizar_criticidad(texto: str | None) -> str | None:
    t = _sin_acentos(texto or "")
    return {"baja": "Baja", "media": "Media", "alta": "Alta", "critica": "Crítica"}.get(t)


def _mover(severidad: str, pasos: int) -> str:
    i = min(max(SEVERIDADES.index(severidad) + pasos, 0), len(SEVERIDADES) - 1)
    return SEVERIDADES[i]


def _es_verdad(valor: Any) -> bool:
    return str(valor).strip().lower() == "true"


# --- 1. Verificar el veredicto --------------------------------------------------------


def _fecha_calendario(texto: str) -> datetime | None:
    """«2026-10-08 08:00» (hora de España) → datetime en UTC."""
    try:
        return datetime.strptime(texto.strip(), "%Y-%m-%d %H:%M").replace(tzinfo=UTC) - DESFASE_ESPANA
    except (AttributeError, ValueError):
        return None


def ips_autorizadas(cambio: dict[str, Any]) -> set[str]:
    """IPs de origen que permite un cambio según su texto («IPs origen 192.0.2.10-12»).

    Vacío = el cambio no restringe el origen por IP.
    """
    texto = f"{cambio.get('detalle', '')} {cambio.get('alcance', '')}"
    ips: set[str] = set()
    for prefijo, desde, hasta in PATRON_IPS.findall(texto):
        for ultimo in range(int(desde), int(hasta or desde) + 1):
            ips.add(f"{prefijo}{ultimo}")
    return ips


def verificar_autorizacion(
    referencia: str, evidencia: dict[str, Any], momento: str = "", ips_alerta: list[str] | None = None
) -> tuple[str, str]:
    """Comprueba la autorización que cita el LLM. Devuelve (autorización, motivo_de_rechazo).

    Vale un CHG-/FLUJO- que esté en los cambios de la evidencia, cuya ventana de fechas
    cubra la hora de la alerta y, si el cambio limita las IPs de origen, cuyo origen
    coincida con el de la alerta. O una regla interna de Tarvia que se cumpla a esa hora.
    El texto que pone el LLM puede venir del atacante, así que nunca basta con citarlo.
    """
    hora = a_fecha(momento)
    cambios = {str(c.get("id", "")).upper(): c for c in evidencia.get("cambios_aprobados", []) if isinstance(c, dict)}
    rechazos: list[str] = []
    for ident in (i.upper() for i in PATRON_CAMBIO.findall(referencia or "")):
        cambio = cambios.get(ident)
        if cambio is None:
            rechazos.append(f"{ident} no aparece en el calendario de cambios consultado")
            continue
        inicio, fin = _fecha_calendario(cambio.get("inicio", "")), _fecha_calendario(cambio.get("fin", ""))
        fechas_ok = hora is None or inicio is None or fin is None or inicio - TOLERANCIA <= hora <= fin + TOLERANCIA
        if not fechas_ok:
            rechazos.append(f"{ident} es del {cambio.get('inicio')} al {cambio.get('fin')} y la alerta es de otro momento")
            continue
        permitidas = ips_autorizadas(cambio)
        if permitidas and not permitidas & set(ips_alerta or []):
            origen = ", ".join(ips_alerta or []) or "una IP desconocida"
            rechazos.append(f"{ident} solo autoriza el origen {', '.join(sorted(permitidas))} y la alerta viene de {origen}")
            continue
        fechas = "fechas sin comprobar" if hora is None or inicio is None or fin is None else f"{cambio.get('inicio')} – {cambio.get('fin')}"
        return f"{ident}: {cambio.get('titulo', '')} ({fechas})", ""
    texto = _sin_acentos(referencia or "")
    for clave, (descripcion, se_cumple) in REGLAS_INTERNAS.items():
        if clave in texto:
            if se_cumple(hora):
                return f"Regla interna: {descripcion}", ""
            rechazos.append(f"la regla interna «{descripcion}» no se cumple a la hora de la alerta")
    return "", "; ".join(rechazos)


# --- 2. Criticidad y severidad ----------------------------------------------------------


def criticidad_afectada(alerta: dict[str, Any], evidencia: dict[str, Any]) -> tuple[str, str]:
    """Criticidad del activo más crítico afectado y de dónde sale."""
    mejores: list[tuple[int, str, str]] = []
    for nombre, activo in (evidencia.get("activos") or {}).items():
        if isinstance(activo, dict) and (c := normalizar_criticidad(activo.get("criticality"))):
            mejores.append((CRITICIDADES.index(c), c, f"activo {nombre} ({activo.get('type', '?')})"))
    if mejores:
        _, c, origen = max(mejores)
        return c, f"Criticidad {c} del {origen}, según la CMDB"
    producto = alerta.get("source_product", "")
    if producto in CRITICIDAD_POR_PRODUCTO:
        c, servicio = CRITICIDAD_POR_PRODUCTO[producto]
        return c, f"Criticidad {c} del servicio afectado: {servicio}"
    return "Media", "Sin activo conocido en la CMDB: se asume criticidad Media (dato a revisar)"


def violaciones_reglas_duras(alerta: dict[str, Any], evidencia: dict[str, Any]) -> list[str]:
    """Reglas internas de empresa_tarvia.md que se pueden comprobar con datos.

    - Solo ENG-WS01 y WMS01 pueden hablar con la red OT; cualquier otro acceso necesita un cambio.
    - Las cuentas adm.* solo pueden usarse desde JUMP01.
    - ext.logisoft (proveedor) solo accede de lunes a viernes, de 8 a 18 h (hora de España).
    """
    entidades = alerta.get("entities") or {}
    hosts = [str(h.get("hostname", "")) for h in entidades.get("hosts", []) if isinstance(h, dict) and h.get("hostname")]
    activos = evidencia.get("activos") or {}

    def es_ot(nombre: str) -> bool:
        a = activos.get(nombre)
        return isinstance(a, dict) and (a.get("zone") == "LOGISTICS-OT" or a.get("type") in TIPOS_OT)

    violaciones = []
    ot = [h for h in hosts if es_ot(h)]
    otros = [h for h in hosts if not es_ot(h) and h.upper() not in HOSTS_PERMITIDOS_OT]
    if ot and otros:
        violaciones.append(f"{', '.join(otros)} se comunica con la red OT ({', '.join(ot)}) y solo pueden ENG-WS01 y WMS01")
    admins = [str(u.get("upn", "")) for u in entidades.get("users", []) if isinstance(u, dict)
              and str(u.get("upn", "")).lower().startswith("adm.")]
    fuera = [h for h in hosts if h.upper() != "JUMP01"]
    if admins and fuera:
        violaciones.append(f"cuenta {', '.join(admins)} usada desde {', '.join(fuera)} (las cuentas adm.* solo desde JUMP01)")
    momento = a_fecha(str(alerta.get("created_at", "")))
    proveedor = any(isinstance(u, dict) and str(u.get("upn", "")).lower().startswith("ext.logisoft")
                    for u in entidades.get("users", []))
    # Sin hora no se puede afirmar que esté fuera de horario: no cuenta como violación.
    if proveedor and momento is not None and not _en_horario_logisoft(momento):
        violaciones.append("cuenta ext.logisoft usada fuera de su horario (lunes a viernes, 8 a 18 h, hora de España)")
    return violaciones


def identidad_privilegiada(evidencia: dict[str, Any]) -> list[str]:
    """Usuarios VIP o privilegiados según el directorio (no según el LLM)."""
    return [
        upn for upn, u in (evidencia.get("usuarios") or {}).items()
        if isinstance(u, dict) and (_es_verdad(u.get("vip")) or _es_verdad(u.get("privileged")) or u.get("account_type") == "admin")
    ]


# --- 4. Contención -----------------------------------------------------------------------


def _activo(target: str, evidencia: dict[str, Any]) -> dict[str, Any] | None:
    for nombre, activo in (evidencia.get("activos") or {}).items():
        if isinstance(activo, dict) and target.lower() in (nombre.lower(), str(activo.get("ip", "")).lower()):
            return activo
    return None


def permisos_accion(action: str, target: str, justification: str, evidencia: dict[str, Any]) -> AccionPolitica:
    """Aplica la tabla de la sección 4: quién aprueba y si está permitida."""
    base = {"action": action, "target": target, "justification": justification}
    activo = _activo(target, evidencia)
    if activo and (activo.get("zone") == "LOGISTICS-OT" or activo.get("type") in TIPOS_OT):
        return AccionPolitica(**base, requires_approval=True, aprobador="Responsable de Operaciones",
                              permitida=False, nota="Red OT: el SOC nunca actúa sobre OT; solo escalar a Operaciones.")
    if action == "purge_email":
        return AccionPolitica(**base, requires_approval=False, aprobador="—", permitida=True)
    if action == "block_ioc":
        if any(d in target.lower() for d in USO_DUAL):
            return AccionPolitica(**base, requires_approval=True, aprobador="N2", permitida=True,
                                  nota="Servicio de uso dual: no se bloquea globalmente sin N2.")
        return AccionPolitica(**base, requires_approval=False, aprobador="—", permitida=True)
    if action == "isolate_host":
        if activo is None:
            return AccionPolitica(**base, requires_approval=True, aprobador="N2", permitida=True,
                                  nota="Equipo no encontrado en la CMDB: confirmar qué es antes de aislar.")
        tipo = activo.get("type", "")
        if tipo in TIPOS_NEGOCIO:
            return AccionPolitica(**base, requires_approval=True, aprobador="N2 + negocio", permitida=True,
                                  nota="Impacto directo en ventas.")
        if tipo == "Portátil":
            return AccionPolitica(**base, requires_approval=True, aprobador="N2", permitida=True)
        servicio = activo.get("business_service") or "servicio afectado"
        return AccionPolitica(**base, requires_approval=True, aprobador=f"N2 + responsable de «{servicio}»",
                              permitida=True, nota="Servidor: ver servicios_negocio.csv.")
    if action == "disable_user" and (target.lower().startswith("svc_") or "svc_" in target.lower()):
        return AccionPolitica(**base, requires_approval=True, aprobador="N2", permitida=True,
                              nota="Cuenta de servicio: deshabilitarla puede parar un proceso de negocio.")
    # revoke_sessions, reset_password, disable_user, disable_access_key
    return AccionPolitica(**base, requires_approval=True, aprobador="N2", permitida=True)


# --- Todo junto ---------------------------------------------------------------------------


def aplicar_politica(alerta: dict[str, Any], evidencia: dict[str, Any], analisis: AnalisisLLM) -> DecisionPolitica:
    avisos: list[str] = []
    senales = analisis.senales

    # 1. Veredicto: benign_true_positive solo con autorización verificable.
    veredicto = analisis.verdict
    entidades = alerta.get("entities") or {}
    ips_alerta = list(entidades.get("ips", [])) + [h.get("ip", "") for h in entidades.get("hosts", []) if h.get("ip")]
    autorizacion, rechazo = verificar_autorizacion(
        senales.referencia_autorizacion, evidencia, alerta.get("created_at", ""), ips_alerta
    )
    if veredicto == "benign_true_positive" and not autorizacion:
        # ¿Hay motivos para desconfiar? Una autorización real que NO encaja (otra fecha,
        # otra IP, una regla que no se cumple) puede ser una tapadera; y si el propio modelo
        # duda o pide escalar, cerrarla sería arriesgado. Entonces: revisión humana.
        no_encaja = any(m in rechazo for m in ("es del", "solo autoriza el origen", "no se cumple"))
        riesgo = no_encaja or analisis.escalar_sugerido or analisis.confidence < CONFIANZA_MINIMA
        detalle = f": {rechazo}" if rechazo else ""
        if riesgo:
            veredicto = "needs_more_info"
            motivo = ("la autorización que alega existe pero no cubre esta alerta, y eso puede ser una tapadera"
                      if no_encaja else "el propio modelo duda o sugiere escalar")
            avisos.append(
                "El modelo dijo benign_true_positive, pero la autorización no se ha podido verificar"
                f"{detalle}. Como {motivo}, no se cierra: pasa a needs_more_info para que lo revise una persona."
            )
        else:
            veredicto = "false_positive"
            avisos.append(
                "El modelo dijo benign_true_positive, pero no citó ninguna autorización verificable "
                "(un cambio o flujo del calendario vigente a la hora de la alerta, o una regla interna "
                f"de Tarvia){detalle}. Se trata como false_positive: revisad que la actividad sea realmente legítima."
            )
    elif rechazo:
        avisos.append(f"El modelo citó una autorización que no se ha podido verificar: {rechazo}.")

    # Reglas duras de Tarvia: si se incumplen y no hay autorización verificada, el código no
    # deja cerrar la alerta como false_positive aunque el modelo lo diga.
    violaciones = [] if autorizacion else violaciones_reglas_duras(alerta, evidencia)
    if violaciones and veredicto in ("false_positive", "benign_true_positive"):
        avisos.append(
            f"El modelo dijo {veredicto}, pero se incumple una regla interna de Tarvia sin cambio aprobado: "
            f"{'; '.join(violaciones)}. No se cierra: pasa a needs_more_info para que lo revise una persona."
        )
        veredicto = "needs_more_info"

    # 2. Severidad.
    sev_regla = alerta.get("severity") if alerta.get("severity") in SEVERIDADES else "medium"
    if sev_regla != alerta.get("severity"):
        avisos.append(f"Severidad de la regla desconocida ({alerta.get('severity')!r}): se asume medium.")

    # Las detecciones críticas (volcado de credenciales, borrado de copias, web shell, sabotaje del EDR...)
    # no las cierra el N1 sin una autorización verificada: un falso positivo aquí cuesta mucho menos que un
    # ataque cerrado por error, y el modelo no siempre es estable (cerró un volcado de LSASS en 1 de 2 pruebas).
    if sev_regla == "critical" and not autorizacion and veredicto in ("false_positive", "benign_true_positive"):
        avisos.append(
            f"El modelo dijo {veredicto}, pero la regla es de severidad crítica y no hay una autorización verificada. "
            "No se cierra: pasa a needs_more_info para que lo revise una persona."
        )
        veredicto = "needs_more_info"
    criticidad, origen = criticidad_afectada(alerta, evidencia)
    base = MATRIZ[sev_regla][CRITICIDADES.index(criticidad)]
    privilegiados = identidad_privilegiada(evidencia)

    motivos: list[str] = []
    ajuste = 0
    if veredicto == "false_positive":
        final = "informational"
        razon = f"Falso positivo: severidad informational (la matriz daría {base})."
    elif veredicto == "benign_true_positive":
        final = "low" if SEVERIDADES.index(base) >= SEVERIDADES.index("medium") else "informational"
        razon = f"Actividad autorizada ({autorizacion}): la política la deja en {final} (la matriz daría {base})."
    else:
        sube = []
        if senales.ejecucion_o_acceso_confirmado:
            sube.append("ejecución o acceso confirmado")
        if senales.identidad_vip_o_privilegiada or privilegiados:
            sube.append("identidad VIP o privilegiada" + (f" ({', '.join(privilegiados)})" if privilegiados else ""))
        if senales.datos_personales_o_pagos:
            sube.append("datos personales o pagos implicados")
        baja = senales.bloqueado_sin_actividad_posterior
        # Máximo un nivel arriba o abajo en total: varios motivos para subir cuentan como +1.
        ajuste = (1 if sube else 0) - (1 if baja else 0)
        motivos = [f"+1: {m}" for m in sube] + (["−1: un control lo bloqueó y no hay actividad posterior"] if baja else [])
        final = _mover(base, ajuste)
        detalle = f" Ajuste {ajuste:+d} ({'; '.join(motivos)})." if motivos else " Sin ajustes."
        razon = f"Regla {sev_regla} × criticidad {criticidad} = {base}.{detalle} Final: {final}."

    # 3. Escalado obligatorio (sección 5).
    motivos_escalado: list[str] = []
    if veredicto == "true_positive":
        if final in ("high", "critical"):
            motivos_escalado.append(f"true_positive de severidad {final}")
        if senales.ejecucion_o_acceso_confirmado:
            motivos_escalado.append("ejecución o acceso confirmado")
        if senales.datos_personales_o_pagos:
            motivos_escalado.append("datos personales o pagos implicados (si han salido, avisar al DPO)")
        if alerta.get("rule_id") in REGLAS_FRAUDE:
            motivos_escalado.append("posible fraude económico")
    if veredicto == "needs_more_info" and final in ("high", "critical"):
        motivos_escalado.append(f"no se puede descartar y la severidad es {final}")
    if analisis.escalar_sugerido and not motivos_escalado:
        avisos.append(f"El modelo sugiere escalar aunque la política no lo exige: {analisis.motivo_escalado or 'sin motivo'}.")

    decision = "escalar" if motivos_escalado else ("revisar" if veredicto == "needs_more_info" else "cerrar")

    # 4. Contención: solo tiene sentido si hay algo malicioso que contener.
    acciones: list[AccionPolitica] = []
    if veredicto in ("true_positive", "needs_more_info"):
        acciones = [permisos_accion(a.action, a.target, a.justification, evidencia) for a in analisis.acciones_sugeridas]
    elif analisis.acciones_sugeridas:
        avisos.append(f"Se descartan {len(analisis.acciones_sugeridas)} acciones sugeridas: el veredicto es {veredicto}.")

    return DecisionPolitica(
        veredicto=veredicto,
        veredicto_llm=analisis.verdict,
        autorizacion=autorizacion,
        criticidad=criticidad,
        origen_criticidad=origen,
        severidad_regla=sev_regla,
        severidad_base=base,
        ajuste=ajuste,
        motivos_ajuste=motivos,
        severidad_final=final,
        razon_severidad=razon,
        decision=decision,
        motivos_escalado=motivos_escalado,
        sla=SLA[final],
        acciones=acciones,
        avisos=avisos,
    )
