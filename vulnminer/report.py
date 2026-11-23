"""Reportes JSON y HTML autocontenido."""

from html import escape

from .io import write_json, write_text

STYLE = """
:root{color-scheme:light;font:15px/1.6 system-ui,sans-serif;background:#f4f6fb;color:#15213a}
body{margin:0 auto;max-width:1060px;padding:32px 22px 64px}
header{background:#14274d;color:#fff;border-radius:16px;padding:22px 28px;margin-bottom:22px}
h1,h2,h3{line-height:1.2;margin-top:0}h1{font-size:clamp(25px,4vw,40px);margin-bottom:8px}
h2{font-size:23px}h3{font-size:17px}.panel{background:#fff;border:1px solid #dce4f1;border-radius:12px;padding:20px;margin:18px 0}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.metric{background:#edf3ff;border-radius:8px;padding:12px}.metric strong{display:block;font-size:25px;color:#234c94}
.meta{margin:8px 0;color:#3d4d68}header .meta{color:#d4e3ff}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;vertical-align:top;border-bottom:1px solid #e0e6f0}
code{overflow-wrap:anywhere}summary{cursor:pointer;font-weight:650}
details{padding:12px 0;border-top:1px solid #e0e6f0}dl{display:grid;grid-template-columns:minmax(120px,.3fr) 1fr;gap:8px}
dt{font-weight:650}dd{margin:0}ul{margin:4px 0;padding-left:22px}.table-wrap{overflow:auto}
@media(max-width:520px){.panel{padding:12px}dl{display:block}dd{margin-bottom:12px}}
"""


def safe(value):
    return escape(str(value))


def bullets(values):
    return "<ul>" + "".join(f"<li>{safe(value)}</li>" for value in values) + "</ul>"


def finding_details(item):
    labels = ", ".join(item["labels"]) or "Pendiente de revisión"
    location = f"{item['file']}:{item['line']}"
    if item["end_line"] != item["line"]:
        location += f"–{item['end_line']}"
    observations = [
        f"{value['description']} (líneas {', '.join(map(str, value['lines']))})"
        for value in item["evidence"]
    ]
    details = (
        ("Identificador", safe(item["id"])),
        ("Ubicación", f"<code>{safe(location)}</code>"),
        ("Estado", safe(item["verification"])),
        ("CWE sugeridas", safe(", ".join(item["cwe"]) or "Por determinar")),
        ("Confianza", f"{item['confidence']:.2%}"),
        ("Severidad", safe(f"{item['severity']}. {item['severity_rationale']}")),
        ("Evidencias", bullets(observations)),
        ("Remediación", bullets(item["remediation"])),
    )
    rows = "".join(f"<dt>{key}</dt><dd>{value}</dd>" for key, value in details)
    return (
        f"<details><summary>{safe(labels)} · {safe(item['description'])}</summary>"
        f"<dl>{rows}</dl></details>"
    )


def table(headers, rows):
    heading = "".join(f"<th scope='col'>{safe(value)}</th>" for value in headers)
    body = "".join("<tr>" + "".join(f"<td>{safe(value)}</td>" for value in row) + "</tr>" for row in rows)
    return f"<div class='table-wrap'><table><thead><tr>{heading}</tr></thead><tbody>{body}</tbody></table></div>"


def html_report(report):
    summary = report["summary"]
    metrics = "".join(
        f"<div class='metric'><strong>{summary[key]}</strong>{label}</div>"
        for key, label in (
            ("services", "Microservicios"), ("files_analyzed", "Archivos analizados"),
            ("potential_findings", "Hallazgos potenciales"), ("classified", "Clasificados"),
            ("pending_review", "Pendientes de revisión"),
        )
    )
    invent = table(("Microservicio", "Ruta", "Tecnologías", "Descubrimiento"), (
        (item["name"], item["path"], ", ".join(item["technologies"]), item["source"])
        for item in report["services"]
    ))
    by_service = {}
    for item in report["findings"]:
        by_service.setdefault(item["service"], []).append(item)
    displayed = "".join(
        f"<section><h3>{safe(service)} · {len(items)}</h3>{''.join(map(finding_details, items))}</section>"
        for service, items in sorted(by_service.items())
    ) or "<p>El análisis no produjo hallazgos potenciales.</p>"
    totals = {}
    for item in report["findings"]:
        for label in item["labels"]:
            totals[label] = totals.get(label, 0) + 1
    categories = table(("Código", "Categoría", "Cobertura", "Hallazgos"), (
        (item["id"], item["name"], item["status"], totals.get(item["id"], 0))
        for item in report["catalog"]
    ))
    skipped = ""
    if report["skipped_files"]:
        rows = table(("Archivo", "Motivo"), ((item["file"], item["reason"]) for item in report["skipped_files"]))
        skipped = f"<section class='panel'><h2>Archivos omitidos</h2>{rows}</section>"
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnMiner · {safe(report["project"])}</title>
<style>{STYLE}</style>
</head>
<body>
<header><p class="meta">VulnMiner</p><h1>{safe(report["project"])}</h1>
<p class="meta">Análisis estático · {safe(report["generated_at"])} · {safe(report["model"]["algorithm"])}</p></header>
<main>
<section class="metrics" aria-label="Resumen">{metrics}</section>
<section class="panel"><h2>Microservicios</h2>{invent}</section>
<section class="panel"><h2>Hallazgos por microservicio</h2>
<p class="meta">Todos los hallazgos requieren verificación. {safe(report["model"]["confidence"])}</p>{displayed}</section>
<section class="panel"><h2>Cobertura y hallazgos por categoría</h2>{categories}</section>
{skipped}
</main>
</body>
</html>"""


def save_reports(report, directory, formats):
    paths = []
    for kind in formats:
        path = directory / f"analisis.{kind}"
        if kind == "json":
            write_json(path, report)
        else:
            write_text(path, html_report(report))
        paths.append(path)
    return paths
