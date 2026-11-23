"""Métricas binarias y multietiqueta calculadas sobre filas independientes."""

from vulnminer.model import RISK, predicted_labels


def confusion(expected, predicted):
    tp = fp = fn = tn = 0
    for actual, guess in zip(expected, predicted):
        if actual and guess:
            tp += 1
        elif guess:
            fp += 1
        elif actual:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": precision, "recall": recall,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
        "support": tp + fn,
        "matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def evaluate(rows, scores, thresholds, labels):
    annotated = [set(row["labels"]) for row in rows]
    predicted = [predicted_labels(score, thresholds, labels) for score in scores]
    binary = [score[RISK] >= thresholds[RISK] for score in scores]
    categories = {
        label: confusion((label in value for value in annotated), (label in value for value in predicted))
        for label in labels
    }
    errors = [
        {
            "id": row["id"], "language": row["language"], "scenario": row["scenario"],
            "false_positive": sorted(guess - actual), "false_negative": sorted(actual - guess),
            "risk_actual": row["vulnerable"], "risk_predicted": classified,
        }
        for row, actual, guess, classified in zip(rows, annotated, predicted, binary)
        if actual != guess or row["vulnerable"] != classified
    ]
    return {
        "records": len(rows),
        "binary": confusion((row["vulnerable"] for row in rows), binary),
        "macro_f1": sum(value["f1"] for value in categories.values()) / len(categories),
        "exact_match": sum(actual == guess for actual, guess in zip(annotated, predicted)) / len(rows),
        "by_category": categories,
        "errors": errors,
    }
