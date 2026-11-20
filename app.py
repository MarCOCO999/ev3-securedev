"""
Aplicación Flask corregida (EV3 SecureDev).

Correcciones aplicadas sobre el código original de la guía 3.2.2:
  1. XSS reflejado     -> la entrada se valida y se escapa con markupsafe.escape.
  2. Modo debug activo -> el modo debug se controla por variable de entorno (apagado por defecto)
                          y en producción la app corre con Gunicorn.
  3. Sin validación    -> lista blanca de caracteres y largo máximo (responde 400 si no cumple).
  4. Sin cabeceras     -> se agregan CSP, X-Frame-Options, X-Content-Type-Options, etc.
"""
import os
import re

from flask import Flask, abort, request
from markupsafe import escape

from monitoring import init_monitoring

app = Flask(__name__)
init_monitoring(app)

NAME_PATTERN = re.compile(r"[A-Za-zÁÉÍÓÚÜÑáéíóúüñ ]{1,50}")

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cache-Control": "no-store",
}


@app.after_request
def add_security_headers(response):
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


@app.route('/hello')
def hello():
    """Saluda al usuario validando y escapando la entrada."""
    name = request.args.get('name', 'invitado')
    if not NAME_PATTERN.fullmatch(name):
        abort(400, description="Parámetro 'name' inválido: solo letras y espacios (máx. 50).")
    return f"Hello, {escape(name)}!"


if __name__ == '__main__':
    # Solo para desarrollo local. En el contenedor se usa Gunicorn (ver Dockerfile).
    app.run(host='127.0.0.1', port=5000, debug=os.getenv("FLASK_DEBUG") == "1")
