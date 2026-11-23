"""Ejecuta la CLI real y contrasta los reportes con anotaciones independientes."""

import json
import subprocess
import sys
from pathlib import Path

from vulnminer.io import write_json

ROOT = Path(__file__).resolve().parents[1]


def compare(expected, report):
    annotated = {
        (row["file"], row["line"], label)
        for row in expected["positive_anchors"] for label in row["labels"]
    }
    matched = set()
    false_positives = []
    for finding in report["findings"]:
        for label in finding["labels"]:
            possible = {
                anchor for anchor in annotated
                if anchor[0] == finding["file"] and anchor[2] == label
                and finding["line"] <= anchor[1] <= finding["end_line"]
            }
            if possible:
                matched.update(possible)
            else:
                false_positives.append((finding["file"], finding["line"], label))
    tp, fp, fn = len(matched), len(false_positives), len(annotated - matched)
    return {
        "services_ok": {item["name"] for item in report["services"]} == set(expected["services"]),
        "languages_ok": set(expected["languages"]) <= report["summary"]["files_by_language"].keys(),
        "expected_anchors": len(expected["positive_anchors"]), "findings": report["summary"]["potential_findings"],
        "matched_categories": sorted({label for _, _, label in matched}),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 0.0,
        "false_positives": sorted(false_positives), "false_negatives": sorted(annotated - matched),
    }


def assess_projects(*, quiet=False):
    examples = ROOT / "examples"
    results = ROOT / "results"
    expectations = json.loads((examples / "expectations.json").read_text(encoding="utf-8"))
    evaluations = {}
    for project, expected in expectations.items():
        output = results / project
        subprocess.run(
            [sys.executable, "-m", "vulnminer", "scan", str(examples / project),
            "--output", str(output)], cwd=ROOT, check=True,
            stdout=subprocess.DEVNULL if quiet else None,
        )
        report = json.loads((output / "analisis.json").read_text(encoding="utf-8"))
        html = (output / "analisis.html").read_text(encoding="utf-8")
        result = compare(expected, report)
        if not result["services_ok"] or not result["languages_ok"]:
            raise RuntimeError(f"El inventario de {project} no coincide con la anotación.")
        if not all(finding["id"] in html for finding in report["findings"]):
            raise RuntimeError(f"El HTML de {project} omitió hallazgos.")
        evaluations[project] = result
    demo = evaluations["demo-microservices"]["matched_categories"]
    if sum(label.startswith("A") and not label.startswith("API") for label in demo) < 5:
        raise RuntimeError("La demostración no alcanzó cinco categorías OWASP Top 10.")
    if sum(label.startswith("API") for label in demo) < 4:
        raise RuntimeError("La demostración no alcanzó cuatro categorías OWASP API Top 10.")
    write_json(results / "project_evaluation.json", evaluations)
    return evaluations


if __name__ == "__main__":
    assess_projects()
