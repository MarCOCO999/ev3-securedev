"""Pruebas funcionales de la aplicación."""
from app import app


def test_hello_con_nombre():
    client = app.test_client()
    respuesta = client.get('/hello?name=Marco')
    assert respuesta.status_code == 200
    assert b"Hello, Marco!" in respuesta.data


def test_metrics_disponible():
    client = app.test_client()
    respuesta = client.get('/metrics')
    assert respuesta.status_code == 200
    assert b"flask_http_request_total" in respuesta.data
