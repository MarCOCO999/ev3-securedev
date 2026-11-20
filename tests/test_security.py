"""
Pruebas automatizadas de seguridad.

Fallan sobre el código vulnerable y pasan cuando las vulnerabilidades
están corregidas.
"""
from app import app

PAYLOAD_XSS = "<script>alert(1)</script>"


def test_xss_reflejado_es_mitigado():
    """La entrada del usuario no debe reflejarse como HTML ejecutable."""
    client = app.test_client()
    respuesta = client.get('/hello', query_string={'name': PAYLOAD_XSS})
    assert PAYLOAD_XSS.encode() not in respuesta.data


def test_entrada_invalida_rechazada():
    """Entradas con caracteres no permitidos deben responder 400."""
    client = app.test_client()
    respuesta = client.get('/hello', query_string={'name': "admin' OR '1'='1"})
    assert respuesta.status_code == 400


def test_cabeceras_de_seguridad():
    """La respuesta debe incluir cabeceras de seguridad básicas."""
    client = app.test_client()
    respuesta = client.get('/hello?name=Marco')
    assert respuesta.headers.get('X-Content-Type-Options') == 'nosniff'
    assert respuesta.headers.get('X-Frame-Options') == 'DENY'
    assert 'Content-Security-Policy' in respuesta.headers


def test_modo_debug_desactivado():
    """El código no debe ejecutar la aplicación con debug=True."""
    with open('app.py', encoding='utf-8') as f:
        assert 'debug=True' not in f.read()
