"""Regenera y ejecuta las celdas de evidencia SEMMA sin instalar Jupyter."""

import contextlib
import io
from pathlib import Path
from textwrap import dedent

from vulnminer.io import write_json

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = """
import json
import sys
from pathlib import Path
root = Path.cwd()
if not (root / "pyproject.toml").is_file():
    root = root.parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))
results = root / "results"
def read(name):
    return json.loads((results / name).read_text(encoding="utf-8"))
"""


def source(text):
    return dedent(text).strip().splitlines(keepends=True)


def markdown(text):
    return {"cell_type": "markdown", "metadata": {}, "source": source(text)}


def code(text):
    return {"cell_type": "code", "metadata": {}, "source": source(text)}


def notebook(name, cells):
    namespace = {}
    counter = 0
    for index, cell in enumerate(cells, 1):
        cell["id"] = f"cell-{index}"
        if cell["cell_type"] == "code":
            counter += 1
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                exec(compile("".join(cell["source"]), name, "exec"), namespace)
            output = buffer.getvalue()
            cell["execution_count"] = counter
            cell["outputs"] = [{"output_type": "stream", "name": "stdout", "text": output.splitlines(keepends=True)}]
    write_json(ROOT / "notebooks" / f"{name}.ipynb", {
        "cells": cells, "nbformat": 4, "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
        },
    })


def render():
    notebook("01_sample", [
        markdown("""
        # Sample · Muestreo

        El corpus combina pares de casos controlados en Java, Python, JavaScript y TypeScript
        con ejemplos de configuración. Los proyectos y referencias están registrados por fila.
        Los fragmentos originales se construyeron a partir de controles descritos por MITRE y OWASP.
        """),
        code(BOOTSTRAP),
        code("""
        from collections import Counter
        from lab.sample import sample
        rows, removals = sample()
        print(len(rows), "registros")
        print("Remociones:", removals)
        print(Counter(row["vulnerable"] for row in rows))
        print(Counter(row["split"] for row in rows))
        memberships = {}
        for row in rows:
            memberships.setdefault(row["project"], set()).add(row["split"])
        assert all(len(split) == 1 for split in memberships.values())
        assert len({row["fingerprint"] for row in rows}) == len(rows)
        print("Proyectos independientes:", sorted(memberships))
        """),
        markdown("El [diccionario](../data/README.md) describe la procedencia, la unidad de análisis y el criterio de partición."),
    ])
    notebook("02_explore", [
        markdown("# Explore · Análisis exploratorio"),
        code(BOOTSTRAP),
        code("""
        from lab.sample import sample
        from lab.train import explore
        rows, removals = sample()
        stats = explore(rows, removals)
        for key in ("raw_records", "clean_records", "removed", "missing_values", "line_count",
                    "languages_and_formats", "vulnerability", "categories"):
            print(key, stats[key])
        print("Observaciones más frecuentes:", sorted(stats["signals"].items(), key=lambda pair: -pair[1])[:8])
        """),
        markdown("""
        ![Registros por categoría](../results/figures/categories.svg)
        ![Registros por clase](../results/figures/binary.svg)
        ![Lenguajes y formatos](../results/figures/languages.svg)
        ![Observaciones más frecuentes](../results/figures/signals.svg)
        ![Prevalencia de etiquetas](../results/figures/imbalance.svg)

        Las dos clases binarias están balanceadas. La prevalencia por etiqueta es menor porque cada
        categoría describe un subconjunto de los ejemplos positivos. Las categorías con frecuencia
        cero quedan fuera del entrenamiento. La mayoría de los registros son fragmentos cortos que
        conservan la operación y el control más cercano.
        """),
    ])
    notebook("03_modify", [
        markdown("""
        # Modify · Transformación

        Se limpia el corpus y se normaliza su huella léxica para eliminar duplicados. El pipeline
        tokeniza palabras y signos, agrega bigramas y observaciones estáticas, aplica TF-IDF
        logarítmico y normaliza los vectores con norma L2. La regresión logística usa pesos
        balanceados para cada problema binario.
        """),
        code(BOOTSTRAP),
        code("""
        from lab.sample import sample
        from vulnminer.features import terms
        from vulnminer.model import fit_vocabulary, vectorize
        rows, _ = sample()
        training = [row for row in rows if row["split"] == "train"]
        vocabulary = fit_vocabulary([terms(row["text"], row["language"]) for row in training])
        row = rows[0]
        transformed = vectorize(terms(row["text"], row["language"]), vocabulary)
        print("Filas:", len(rows), "Columnas:", len(vocabulary))
        print("Primera fila de la matriz dispersa:", row["id"], row["split"], sorted(transformed.items())[:8])
        print("Observaciones en el vocabulario:", [term for term in vocabulary if term.startswith("signal:")])
        """),
        markdown("El vocabulario y las ponderaciones IDF se ajustan con entrenamiento y se reutilizan en validación, prueba e inferencia."),
    ])
    notebook("04_model", [
        markdown("""
        # Model · Entrenamiento

        Se entrenan regresión logística y Naive Bayes multinomial con una salida binaria de riesgo
        y una salida por etiqueta. Se prueban dos hiperparámetros por algoritmo y se ajustan los
        umbrales con validación. El modelo y el vocabulario se serializan en JSON.
        """),
        code(BOOTSTRAP),
        code("""
        from lab.train import train
        train()
        """),
        code("""
        evaluation = read("evaluation.json")
        for trial in evaluation["trials"]:
            print(trial["algorithm"], trial["parameter"], "F1 macro de validación:", round(trial["validation"]["macro_f1"], 4))
        print("Seleccionado:", evaluation["selected"], "parámetro:", evaluation["parameter"])
        print(evaluation["selection"])
        artifact = json.loads((root / "vulnminer" / "model.json").read_text(encoding="utf-8"))
        print("Umbrales:", artifact["thresholds"])
        """),
        markdown("![F1 macro comparativo](../results/figures/model_comparison.svg)"),
    ])
    notebook("05_assess", [
        markdown("# Assess · Prueba independiente y evaluación de la CLI"),
        code(BOOTSTRAP),
        code("""
        evaluation = read("evaluation.json")
        for result in evaluation["comparison"]:
            test = result["test"]
            print(result["algorithm"], "F1 macro:", test["macro_f1"], "Binario:", test["binary"])
        test = next(item["test"] for item in evaluation["comparison"] if item["algorithm"] == evaluation["selected"])
        for label, metric in test["by_category"].items():
            print(label, "P/R/F1", *(round(metric[key], 3) for key in ("precision", "recall", "f1")), metric["matrix"])
        print("Errores en la partición de prueba:", test["errors"])
        """),
        code("""
        from lab.assess_projects import assess_projects
        for name, result in assess_projects(quiet=True).items():
            print(name, {key: result[key] for key in ("tp", "fp", "fn", "precision", "recall", "f1")})
            print("Falsos positivos:", result["false_positives"])
            print("Falsos negativos:", result["false_negatives"])
        """),
        markdown("""
        ![F1 por categoría](../results/figures/test_categories.svg)

        La prueba por fragmentos comparte convenciones con los datos de entrenamiento. En el
        segundo proyecto un control de acceso con nombre fuera del vocabulario origina un falso
        positivo y una operación de exportación sin límite pasa inadvertida en la localización
        estática. Los resultados de los proyectos son medidas por etiqueta y ubicación anotada.
        """),
    ])


if __name__ == "__main__":
    render()
