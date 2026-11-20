# Política de gestión de dependencias y parcheo

## 1. Inventario
- Todas las dependencias se declaran en `requirements.txt` con **versión fija** (`paquete==x.y.z`).
- La imagen base de Docker se declara con versión explícita en el `Dockerfile`.

## 2. Detección automática
| Control | Herramienta | Cuándo |
|---|---|---|
| CVE en dependencias Python | pip-audit | Cada ejecución del pipeline |
| CVE en dependencias (NVD) | OWASP Dependency-Check | Cada ejecución del pipeline |
| Nuevas versiones y avisos de seguridad | GitHub Dependabot | Semanal + alertas inmediatas |

## 3. Plazos de corrección según severidad
| Severidad (CVSS) | Plazo máximo | Acción |
|---|---|---|
| Crítica (9.0 – 10.0) | 48 horas | Bloquea el despliegue a producción |
| Alta (7.0 – 8.9) | 7 días | Bloquea el despliegue a producción |
| Media (4.0 – 6.9) | 30 días | Se planifica en el siguiente sprint |
| Baja (0.1 – 3.9) | 90 días | Se revisa en mantenimiento |

## 4. Procedimiento de parcheo
1. Dependabot o el pipeline detectan una versión vulnerable.
2. Se crea una rama / Pull Request con la versión corregida.
3. El pipeline ejecuta pruebas funcionales, pruebas de seguridad, SAST, revisión de dependencias y DAST.
4. Solo si el pipeline termina sin hallazgos críticos/altos se hace merge a `main`.
5. El commit, el número de build y los reportes archivados en Jenkins quedan como evidencia para auditoría.

## 5. Excepciones
Una vulnerabilidad que no pueda corregirse en el plazo debe documentarse con: justificación, control compensatorio y fecha de revisión, aprobada por el responsable de seguridad.
