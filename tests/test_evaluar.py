"""Tests de scripts/evaluar.py: cómo se puntúan veredicto, severidad y decisión (sin red)."""

from scripts.evaluar import fallos, informe, observado, puntuar


def resultado(veredicto="true_positive", severidad="high", decision="escalar"):
    return {"politica": {"veredicto": veredicto, "severidad_final": severidad, "decision": decision}}


CASO = {
    "alert_id": "ALR-1", "categoria": "incidente", "veredictos_validos": ["true_positive"],
    "severidades_validas": ["high", "critical"], "decisiones_validas": ["escalar"],
}


def test_un_resultado_correcto_acierta_las_tres_metricas():
    assert puntuar(CASO, resultado()) == {"veredicto": True, "severidad": True, "decision": True}


def test_cada_metrica_falla_por_separado():
    assert puntuar(CASO, resultado(severidad="low")) == {"veredicto": True, "severidad": False, "decision": True}
    assert puntuar(CASO, resultado(decision="cerrar")) == {"veredicto": True, "severidad": True, "decision": False}
    assert puntuar(CASO, resultado("false_positive", "informational", "cerrar")) == {
        "veredicto": False, "severidad": False, "decision": False}


def test_sin_etiqueta_la_metrica_no_se_mide():
    caso = {"alert_id": "ALR-2", "categoria": "ruido", "veredictos_validos": ["false_positive"]}
    assert puntuar(caso, resultado("false_positive", "informational", "cerrar")) == {
        "veredicto": True, "severidad": None, "decision": None}


def test_un_error_del_triaje_cuenta_como_fallo_no_como_no_medido():
    assert observado({"error": "TimeoutError"})["veredicto"] == "ERROR: TimeoutError"
    assert puntuar(CASO, {"error": "TimeoutError"}) == {"veredicto": False, "severidad": False, "decision": False}


def fila(caso, *resultados):
    obtenidos = [observado(r) for r in resultados]
    puntos = [puntuar(caso, r) for r in resultados]
    return {**caso, "veredictos": [o["veredicto"] for o in obtenidos], "obtenidos": obtenidos, "puntos": puntos,
            "aciertos": sum(p["veredicto"] for p in puntos), "total": len(puntos),
            "estable": len({o["veredicto"] for o in obtenidos}) == 1}


def test_el_informe_resume_cada_metrica_y_lista_los_fallos():
    filas = [fila(CASO, resultado(), resultado(severidad="low", decision="revisar"))]
    texto = informe(filas)
    assert "VEREDICTO  2/2 (100 %)" in texto
    assert "SEVERIDAD  1/2 (50 %)" in texto
    assert "DECISION   1/2 (50 %)" in texto
    assert [m.strip().split()[2] for m in fallos(filas)] == ["severidad", "decision"]
    assert "esperado high | critical → obtenido low" in texto
