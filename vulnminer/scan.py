"""Une el inventario, las observaciones estáticas y el modelo serializado."""

import hashlib
from collections import Counter
from datetime import datetime, timezone

from .catalog import BY_LABEL, CATALOG, SEVERITY_ORDER, STANDARDS
from .features import PATTERNS, candidates
from .project import inventory, read_source, service_path


def scan(root, output, standards, model):
    tree = inventory(root, output)
    active_labels = set().union(*(STANDARDS[name] for name in standards))
    report = {
        "schema_version": 1, "project": root.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "standards": list(standards), "model": {
            "algorithm": model.artifact["algorithm"], "sha256": model.artifact["sha256"],
            "confidence": "Puntaje del clasificador sin calibración en entornos de producción.",
        },
        "catalog": [
            {"id": label, "name": name, "status": "Evaluada" if label in model.labels else "No evaluada"}
            for label, name in CATALOG.items() if label in active_labels
        ],
        "services": [
            {"name": service["name"], "path": path.relative_to(root).as_posix(),
             "technologies": sorted(service["technologies"]), "source": service["source"]}
            for path, service in sorted(tree.services.items())
        ],
        "findings": [], "skipped_files": list(tree.skipped),
    }
    counts = Counter()
    n_candidates = 0
    for path, language in tree.files:
        relative = path.relative_to(root).as_posix()
        try:
            text = read_source(path)
        except (OSError, ValueError) as error:
            if not any(item["file"] == relative for item in report["skipped_files"]):
                report["skipped_files"].append({"file": relative, "reason": str(error)})
            continue
        counts[language] += 1
        scope = service_path(path.parent, tree.services)
        service = tree.services[scope]["name"] if scope is not None else "(configuración raíz)"
        for candidate in candidates(text):
            n_candidates += 1
            confidence, labels, probabilities = model.predict(candidate.text, language)
            included = labels & active_labels
            if labels and not included:
                continue
            if not included and confidence < model.artifact["review_threshold"]:
                continue
            report["findings"].append(
                finding(relative, service, language, candidate, included, confidence, probabilities, active_labels)
            )
    findings = report["findings"]
    report["summary"] = {
        "services": len(tree.services), "files_analyzed": sum(counts.values()), "files_by_language": dict(counts),
        "candidates": n_candidates, "potential_findings": len(findings),
        "classified": sum(bool(f["labels"]) for f in findings),
        "pending_review": sum(not f["labels"] for f in findings),
        "confirmed": 0,
    }
    return report


def finding(path, service, language, candidate, labels, confidence, probabilities, active_labels):
    ordered = sorted(labels)
    metadata = list(dict.fromkeys(BY_LABEL[label] for label in ordered))
    probable = bool(ordered)
    if probable:
        severity = max((item[1] for item in metadata), key=SEVERITY_ORDER.get)
        justification = " ".join(item[2] for item in metadata)
        description = "Posible " + " / ".join(dict.fromkeys(CATALOG[label] for label in ordered))
        recommendations = [item[3] for item in metadata]
    else:
        severity = "Por determinar"
        justification = "Hace falta verificar el contexto y el impacto del patrón."
        description = "Patrón con evidencia insuficiente para asignar una categoría."
        recommendations = ["Revisar el control relevante y el contexto de ejecución."]
    digest = hashlib.sha256(f"{path}:{candidate.line}:{candidate.end_line}".encode()).hexdigest()[:12]
    return {
        "id": f"VM-{digest}", "service": service, "file": path, "language": language,
        "line": candidate.line, "end_line": candidate.end_line, "description": description,
        "evidence": [
            {"signal": key, "description": PATTERNS[key][1], "lines": locations}
            for key, locations in candidate.observations.items()
        ],
        "labels": ordered,
        "owasp_top10_2025": [label for label in ordered if label in STANDARDS["owasp2025"]],
        "owasp_api_top10_2023": [label for label in ordered if label in STANDARDS["api2023"]],
        "cwe": sorted({item[0] for item in metadata}), "confidence": round(confidence, 5),
        "label_scores": {label: round(score, 5) for label, score in probabilities.items() if label in active_labels},
        "severity": severity, "severity_rationale": justification,
        "remediation": recommendations, "verification": "Requiere verificación" if probable else "Pendiente de revisión",
        "confirmed": False,
    }
