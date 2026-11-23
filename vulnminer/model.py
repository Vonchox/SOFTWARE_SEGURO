"""TF-IDF disperso y dos clasificadores supervisados multietiqueta."""

import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass
from importlib.resources import files

from .catalog import CATALOG
from .features import terms

RISK = "risk"
MODEL_VERSION = 1


def sigmoid(value):
    return 1 / (1 + math.exp(-max(-700, min(700, value))))


def fit_vocabulary(documents):
    frequency = Counter(term for document in documents for term in document)
    retained = sorted(term for term, count in frequency.items() if count >= 2)
    return {
        term: (index, math.log((1 + len(documents)) / (1 + frequency[term])) + 1)
        for index, term in enumerate(retained)
    }


def vectorize(document, vocabulary):
    vector = {}
    for term, count in document.items():
        if term in vocabulary:
            index, idf = vocabulary[term]
            multiplier = 2.6 if term.startswith("signal:") else 1
            vector[index] = multiplier * (1 + math.log(count)) * idf
    norm = math.sqrt(sum(value * value for value in vector.values()))
    return {index: value / norm for index, value in vector.items()} if norm else {}


def learn_logistic(vectors, target, size, regularization, epochs=100):
    positive = sum(target)
    negative = len(target) - positive
    sample_weights = [0.5 / (positive if actual else negative) for actual in target]
    weights = [0.0] * size
    bias = 0.0
    for epoch in range(epochs):
        gradient = [regularization * value for value in weights]
        bias_gradient = 0
        for vector, actual, sample_weight in zip(vectors, target, sample_weights):
            score = bias + sum(weights[index] * value for index, value in vector.items())
            error = (sigmoid(score) - actual) * sample_weight
            bias_gradient += error
            for index, value in vector.items():
                gradient[index] += error * value
        step = 2.0 / math.sqrt(1 + epoch / 32)
        weights = [value - step * change for value, change in zip(weights, gradient)]
        bias -= step * bias_gradient
    return {"bias": bias, "weights": weights}


def learn_naive_bayes(vectors, target, size, smoothing):
    counts = [[smoothing] * size, [smoothing] * size]
    for vector, actual in zip(vectors, target):
        for index, value in vector.items():
            counts[actual][index] += value
    negative, positive = counts
    negative_total, positive_total = sum(negative), sum(positive)
    # Prior balanceado para etiquetas de baja frecuencia.
    weights = [math.log(p / positive_total) - math.log(n / negative_total) for n, p in zip(negative, positive)]
    return {"bias": 0.0, "weights": weights}


def fit_heads(vectors, truth, labels, size, algorithm, parameter):
    learn = {"logistic": learn_logistic, "multinomial_nb": learn_naive_bayes}[algorithm]
    return {
        label: learn(vectors, [int(label in row) for row in truth], size, parameter)
        for label in (RISK, *labels)
    }


def scores_for(vector, heads):
    return {
        label: sigmoid(head["bias"] + sum(head["weights"][index] * value for index, value in vector.items()))
        for label, head in heads.items()
    }


def predicted_labels(scores, thresholds, labels):
    if scores[RISK] < thresholds[RISK]:
        return set()
    return {label for label in labels if scores[label] >= thresholds[label]}


@dataclass(frozen=True)
class Model:
    artifact: dict

    @classmethod
    def load(cls):
        raw = files("vulnminer").joinpath("model.json").read_bytes()
        artifact = json.loads(raw)
        if artifact["version"] != MODEL_VERSION:
            raise ValueError("La versión del modelo serializado no es compatible.")
        labels = artifact["labels"]
        if not set(labels) <= CATALOG.keys():
            raise ValueError("El modelo contiene etiquetas OWASP desconocidas.")
        return cls(artifact | {"sha256": hashlib.sha256(raw).hexdigest()})

    @property
    def labels(self):
        return self.artifact["labels"]

    def predict(self, text, language):
        vector = vectorize(terms(text, language), self.artifact["vocabulary"])
        scores = scores_for(vector, self.artifact["heads"])
        thresholds = self.artifact["thresholds"]
        return (
            scores[RISK],
            predicted_labels(scores, thresholds, self.labels),
            {label: scores[label] for label in self.labels},
        )
