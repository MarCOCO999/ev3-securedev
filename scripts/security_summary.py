#!/usr/bin/env python3
"""
Consolida los reportes de seguridad del pipeline en security-summary.md.

Lee (si existen): build-info.txt, test-results.xml, bandit-report.json,
pip-audit.json, dependency-check-report.json y zap-report.json.

Código de salida:
  0 -> sin hallazgos de severidad alta/crítica
  2 -> hay hallazgos de severidad alta/crítica (el pipeline queda UNSTABLE)
"""
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import Counter

OUT = "security-summary.md"


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def section_tests(lines):
    path = "test-results.xml"
    if not os.path.exists(path):
        lines.append("_Sin resultados de pruebas._\n")
        return 0
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    total = failed = 0
    failing = []
    for s in suites:
        for case in s.findall("testcase"):
            total += 1
            if case.find("failure") is not None or case.find("error") is not None:
                failed += 1
                failing.append(f"{case.get('classname')}.{case.get('name')}")
    lines.append(f"| Pruebas ejecutadas | Aprobadas | Fallidas |\n|---|---|---|\n| {total} | {total - failed} | {failed} |\n")
    if failing:
        lines.append("Pruebas fallidas:\n")
        lines += [f"- `{name}`" for name in failing]
        lines.append("")
    return failed


def section_bandit(lines):
    data = load_json("bandit-report.json")
    if data is None:
        lines.append("_Reporte no disponible._\n")
        return 0
    results = data.get("results", [])
    sev = Counter(r.get("issue_severity", "UNDEFINED") for r in results)
    lines.append("| Alta | Media | Baja |\n|---|---|---|\n"
                 f"| {sev.get('HIGH', 0)} | {sev.get('MEDIUM', 0)} | {sev.get('LOW', 0)} |\n")
    if results:
        lines.append("| Severidad | Regla | Ubicación | Descripción |\n|---|---|---|---|")
        for r in results:
            lines.append(f"| {r.get('issue_severity')} | {r.get('test_id')} | "
                         f"{r.get('filename')}:{r.get('line_number')} | {r.get('issue_text')} |")
        lines.append("")
    return sev.get("HIGH", 0)


def section_pip_audit(lines):
    data = load_json("pip-audit.json")
    if data is None:
        lines.append("_Reporte no disponible._\n")
        return 0
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    rows = []
    for d in deps:
        for v in d.get("vulns", []):
            fixes = ", ".join(v.get("fix_versions", [])) or "sin versión corregida"
            aliases = ", ".join(a for a in v.get("aliases", []) if a.startswith("CVE")) or "-"
            rows.append(f"| {d.get('name')} | {d.get('version')} | {v.get('id')} | {aliases} | {fixes} |")
    lines.append(f"Vulnerabilidades conocidas en dependencias: **{len(rows)}**\n")
    if rows:
        lines.append("| Paquete | Versión | ID | CVE | Versión corregida |\n|---|---|---|---|---|")
        lines += rows
        lines.append("")
    return len(rows)


def section_dependency_check(lines):
    data = load_json("dependency-check-report.json")
    if data is None:
        lines.append("_Reporte no disponible (etapa omitida o sin resultados)._\n")
        return 0
    sev = Counter()
    rows = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []) or []:
            s = (v.get("severity") or "UNKNOWN").upper()
            sev[s] += 1
            rows.append(f"| {dep.get('fileName')} | {v.get('name')} | {s} |")
    lines.append("| Crítica | Alta | Media | Baja |\n|---|---|---|---|\n"
                 f"| {sev.get('CRITICAL', 0)} | {sev.get('HIGH', 0)} | {sev.get('MEDIUM', 0)} | {sev.get('LOW', 0)} |\n")
    if rows:
        lines.append("| Dependencia | CVE | Severidad |\n|---|---|---|")
        lines += rows
        lines.append("")
    return sev.get("CRITICAL", 0) + sev.get("HIGH", 0)


def section_zap(lines):
    data = load_json("zap-report.json")
    if data is None:
        lines.append("_Reporte no disponible._\n")
        return 0
    risk_names = {"3": "Alta", "2": "Media", "1": "Baja", "0": "Informativa"}
    counts = Counter()
    rows = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            code = str(a.get("riskcode", "0"))
            counts[code] += 1
            rows.append((code, f"| {risk_names.get(code, code)} | {a.get('name') or a.get('alert')} | "
                               f"CWE-{a.get('cweid', '-')} | {a.get('count', len(a.get('instances', [])))} |"))
    lines.append("| Alta | Media | Baja | Informativa |\n|---|---|---|---|\n"
                 f"| {counts.get('3', 0)} | {counts.get('2', 0)} | {counts.get('1', 0)} | {counts.get('0', 0)} |\n")
    if rows:
        lines.append("| Riesgo | Alerta | CWE | Instancias |\n|---|---|---|---|")
        lines += [r for _, r in sorted(rows, key=lambda x: x[0], reverse=True)]
        lines.append("")
    return counts.get("3", 0)


def main():
    lines = ["# Resumen de seguridad del pipeline\n"]
    if os.path.exists("build-info.txt"):
        with open("build-info.txt", encoding="utf-8") as f:
            lines.append("```\n" + f.read().strip() + "\n```\n")

    lines.append("## 1. Pruebas (funcionales y de seguridad)\n")
    failed_tests = section_tests(lines)
    lines.append("## 2. Análisis estático - Bandit (SAST)\n")
    bandit_high = section_bandit(lines)
    lines.append("_El análisis de SonarQube se consulta en el servidor SonarQube (proyecto ev3-securedev)._\n")
    lines.append("## 3. Dependencias - pip-audit\n")
    pip_vulns = section_pip_audit(lines)
    lines.append("## 4. Dependencias - OWASP Dependency-Check\n")
    odc_high = section_dependency_check(lines)
    lines.append("## 5. Análisis dinámico - OWASP ZAP (DAST)\n")
    zap_high = section_zap(lines)

    high_total = bandit_high + pip_vulns + odc_high + zap_high
    lines.append("## Resultado\n")
    lines.append("| Indicador | Valor |\n|---|---|")
    lines.append(f"| Pruebas fallidas | {failed_tests} |")
    lines.append(f"| Bandit severidad alta | {bandit_high} |")
    lines.append(f"| Dependencias con CVE (pip-audit) | {pip_vulns} |")
    lines.append(f"| Dependency-Check crítica/alta | {odc_high} |")
    lines.append(f"| ZAP riesgo alto | {zap_high} |")
    estado = "NO APTO - requiere corrección" if (high_total or failed_tests) else "APTO - sin hallazgos críticos"
    lines.append(f"\n**Estado de seguridad: {estado}**\n")

    report = "\n".join(lines)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    sys.exit(2 if high_total else 0)


if __name__ == "__main__":
    main()
