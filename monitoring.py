"""
Instrumentación de monitoreo para Prometheus / Grafana.

- Expone métricas HTTP estándar en /metrics (prometheus_flask_exporter).
- Cuenta solicitudes con patrones de ataque (XSS, SQLi, path traversal,
  inyección de comandos) en la métrica suspicious_requests_total, para
  detectar incidentes de seguridad en tiempo real desde Grafana.
"""
import re
from urllib.parse import unquote_plus

from flask import request
from prometheus_client import Counter
from prometheus_flask_exporter import PrometheusMetrics

ATTACK_PATTERNS = {
    "xss": re.compile(r"<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*(img|svg|iframe)|alert\s*\(", re.I),
    "sqli": re.compile(r"('|\")\s*(or|and)\s+.*=|union\s+(all\s+)?select|;\s*drop\s+table|sleep\s*\(", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.\\|/etc/passwd|win\.ini", re.I),
    "cmd_injection": re.compile(r";\s*(ls|cat|id|whoami|uname)\b|\|\s*(ls|cat|id|whoami)\b|`|\$\(", re.I),
}

SUSPICIOUS_REQUESTS = Counter(
    "suspicious_requests_total",
    "Solicitudes que contienen patrones de ataque conocidos",
    ["attack_type"],
)


def init_monitoring(app):
    metrics = PrometheusMetrics(app, group_by="endpoint")
    metrics.info("app_info", "Información de la aplicación", app="ev3-securedev")

    @app.before_request
    def detect_attacks():
        if request.path == "/metrics":
            return
        data = request.path + " " + unquote_plus(request.query_string.decode("utf-8", "ignore"))
        for attack_type, pattern in ATTACK_PATTERNS.items():
            if pattern.search(data):
                SUSPICIOUS_REQUESTS.labels(attack_type=attack_type).inc()
                app.logger.warning(
                    "SECURITY_ALERT tipo=%s ip=%s ruta=%s", attack_type, request.remote_addr, request.full_path
                )

    return metrics
