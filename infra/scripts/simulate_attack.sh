#!/bin/sh
# Simula tráfico malicioso contra la aplicación para probar el monitoreo en Grafana.
T="${TARGET:-http://ev3-app:5000}"
echo "Simulando ataque contra $T (60 segundos aprox.)"
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "%{http_code}  XSS\n"            "$T/hello?name=%3Cscript%3Ealert($i)%3C%2Fscript%3E"
  curl -s -o /dev/null -w "%{http_code}  SQLi\n"           "$T/hello?name=admin%27%20OR%20%271%27%3D%271"
  curl -s -o /dev/null -w "%{http_code}  Path traversal\n" "$T/hello?name=..%2F..%2Fetc%2Fpasswd"
  curl -s -o /dev/null -w "%{http_code}  Escaneo rutas\n"  "$T/admin$i"
  curl -s -o /dev/null -w "%{http_code}  Normal\n"         "$T/hello?name=Usuario$i"
  sleep 2
done
echo "Simulación terminada."
