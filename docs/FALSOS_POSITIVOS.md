# Registro de falsos positivos

| ID | Herramienta | Regla | Fecha | Analizado por | Estado |
|---|---|---|---|---|---|
| FP-001 | OWASP ZAP | 43 - Source Code Disclosure - File Inclusion | 2026-11-20 | Marco Contreras | Suprimida en `zap-rules.tsv` |

## FP-001 – Source Code Disclosure - File Inclusion (ZAP 43)

**Alerta:** ZAP reporta riesgo alto en `GET /hello?name=test`, sospechando que el parámetro `name` permite incluir archivos del servidor y revelar código fuente.

**Análisis:**
- La aplicación no abre, lee ni incluye archivos: el parámetro `name` solo se usa para construir el texto `Hello, <name>!`.
- La regla de ZAP compara respuestas al enviar nombres de archivo en el parámetro; como la aplicación refleja el valor recibido, las respuestas cambian y la regla lo interpreta como inclusión de archivos.
- La entrada está restringida por lista blanca (solo letras y espacios, máx. 50), por lo que no es posible enviar rutas (`/`, `.`, `..`).
- El código fue revisado manualmente y por Bandit y SonarQube, sin hallazgos relacionados.

**Decisión:** falso positivo. Se suprime la regla 43 en el escaneo de ZAP mediante `zap-rules.tsv`.

**Revisión:** reevaluar si la aplicación incorpora funcionalidades que lean archivos.
