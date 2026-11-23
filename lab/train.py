"""Ejecuta Sample, Explore, Modify, Model y Assess en orden reproducible."""

from collections import Counter
from pathlib import Path
from statistics import median

from vulnminer.catalog import CATALOG
from vulnminer.features import observations, terms, without_comments
from vulnminer.io import write_json, write_jsonl
from vulnminer.model import MODEL_VERSION, RISK, fit_heads, fit_vocabulary, scores_for, vectorize

from .charts import bars
from .metrics import confusion, evaluate
from .sample import raw_records, sample

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RESULTS = ROOT / "results"
TRIALS = {"logistic": (0.008, 0.025), "multinomial_nb": (0.06, 0.3)}


def explore(records, removals):
    by_category = Counter(label for row in records for label in row["labels"])
    by_language = Counter(row["language"] for row in records)
    by_class = Counter("Vulnerable" if row["vulnerable"] else "No vulnerable" for row in records)
    by_signal = Counter(signal for row in records for signal in observations(without_comments(row["text"])))
    line_counts = [len(row["text"].splitlines()) for row in records]
    corpus = {
        "raw_records": sum(1 for _ in raw_records()),
        "clean_records": len(records),
        "removed": removals,
        "missing_values": sum(
            any(not row.get(key) for key in ("id", "text", "language", "project", "references"))
            for row in records
        ),
        "partitions": {
            name: {"size": len(group), "projects": sorted({row["project"] for row in group})}
            for name in ("train", "validation", "test")
            for group in [[row for row in records if row["split"] == name]]
        },
        "categories": {label: by_category[label] for label in CATALOG},
        "languages_and_formats": dict(by_language),
        "vulnerability": dict(by_class),
        "signals": dict(by_signal),
        "line_count": {"min": min(line_counts), "median": median(line_counts), "max": max(line_counts)},
    }
    figures = RESULTS / "figures"
    bars(figures / "categories.svg", "Registros por categoría OWASP", corpus["categories"].items())
    bars(figures / "binary.svg", "Ejemplos vulnerables y no vulnerables", by_class.items())
    bars(figures / "languages.svg", "Lenguajes y formatos del corpus", by_language.most_common())
    bars(figures / "signals.svg", "Observaciones estáticas más frecuentes", by_signal.most_common(15))
    bars(figures / "imbalance.svg", "Prevalencia de etiquetas en el corpus",
         ((label, by_category[label] / len(records)) for label in CATALOG), domain=1)
    return corpus


def best_threshold(entries, preferred=0.5):
    choices = (0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90)
    ranked = []
    for cut in choices:
        result = confusion(
            (actual for actual, _, _ in entries),
            (allowed and score >= cut for _, score, allowed in entries),
        )
        ranked.append((result["f1"], result["precision"], -abs(cut - preferred), cut))
    return max(ranked)[-1]


def tune_thresholds(validation, scores, labels):
    risk = best_threshold([(row["vulnerable"], score[RISK], True) for row, score in zip(validation, scores)])
    return {RISK: risk} | {
        label: best_threshold([
            (label in row["labels"], score[label], score[RISK] >= risk)
            for row, score in zip(validation, scores)
        ], preferred=0.58)
        for label in labels
    }


def train():
    records, removals = sample()
    write_jsonl(DATA / "dataset.jsonl", records)
    write_json(RESULTS / "explore.json", explore(records, removals))
    documents = {row["id"]: terms(row["text"], row["language"]) for row in records}
    parts = {
        name: [row for row in records if row["split"] == name]
        for name in ("train", "validation", "test")
    }
    training = parts["train"]
    validation = parts["validation"]
    test = parts["test"]
    labels = sorted({label for row in training for label in row["labels"]})
    for name, part in parts.items():
        if {label for row in part for label in row["labels"]} != set(labels):
            raise ValueError(f"La partición {name} no representa las mismas categorías.")
    vocabulary = fit_vocabulary([documents[row["id"]] for row in training])
    vectors = {identifier: vectorize(document, vocabulary) for identifier, document in documents.items()}
    write_json(RESULTS / "features.json", {
        "rows": len(records), "columns": len(vocabulary), "features": list(vocabulary),
        "transform": "TF-IDF logarítmico, normalización L2 y ponderación de observaciones",
    })
    write_jsonl(RESULTS / "matrix.jsonl", (
        {"id": row["id"], "split": row["split"], "values": sorted(vectors[row["id"]].items())} for row in records
    ))
    truth = [set(row["labels"]) | ({RISK} if row["vulnerable"] else set()) for row in training]
    x_train = [vectors[row["id"]] for row in training]
    trials = []
    finalists = []
    for algorithm, parameters in TRIALS.items():
        options = []
        for parameter in parameters:
            heads = fit_heads(x_train, truth, labels, len(vocabulary), algorithm, parameter)
            scores = [scores_for(vectors[row["id"]], heads) for row in validation]
            thresholds = tune_thresholds(validation, scores, labels)
            evaluation = evaluate(validation, scores, thresholds, labels)
            trial = {"algorithm": algorithm, "parameter": parameter, "thresholds": thresholds, "validation": evaluation}
            trials.append(trial)
            options.append((trial, heads))
        finalists.append(max(options, key=rank))
    champion, heads = max(finalists, key=rank)
    comparison = [
        {
            **trial,
            "test": evaluate(
                test, [scores_for(vectors[row["id"]], classifier) for row in test], trial["thresholds"], labels
            ),
        }
        for trial, classifier in finalists
    ]
    selected = next(item for item in comparison if item["algorithm"] == champion["algorithm"])
    write_json(RESULTS / "evaluation.json", {
        "selection": (
            "Mayor F1 macro en validación. Desempate por F1 binario y coincidencia exacta. "
            "Si persiste el empate se usa el primer candidato del orden declarado. La regresión logística "
            "tiene prioridad porque ajusta cada salida sin asumir independencia entre observaciones."
        ),
        "selected": champion["algorithm"], "parameter": champion["parameter"],
        "evaluated_labels": labels, "not_evaluated": [label for label in CATALOG if label not in labels],
        "trials": trials, "comparison": comparison,
    })
    bars(RESULTS / "figures" / "model_comparison.svg", "F1 macro en validación y prueba", (
        (f"{item['algorithm']} · {phase}", item[phase]["macro_f1"])
        for item in comparison for phase in ("validation", "test")
    ), domain=1)
    bars(RESULTS / "figures" / "test_categories.svg", "F1 por categoría en la prueba independiente", (
        (label, selected["test"]["by_category"][label]["f1"]) for label in labels
    ), domain=1)
    model = {
        "version": MODEL_VERSION, "algorithm": champion["algorithm"], "parameter": champion["parameter"],
        "labels": labels, "thresholds": champion["thresholds"], "vocabulary": vocabulary, "heads": heads,
        "review_threshold": max(0.35, champion["thresholds"][RISK] - 0.08),
    }
    write_json(ROOT / "vulnminer" / "model.json", model, compact=True)
    print(f"{len(records)} registros. Modelo: {champion['algorithm']}. F1 macro de prueba: {selected['test']['macro_f1']:.3f}.")


def rank(option):
    metrics = option[0]["validation"]
    return metrics["macro_f1"], metrics["binary"]["f1"], metrics["exact_match"]


if __name__ == "__main__":
    train()
