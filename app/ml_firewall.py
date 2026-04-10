from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from app.config import get_settings
from app.retriever import SentenceTransformerEncoder

VALID_LABELS = ("safe", "suspicious", "malicious")


@dataclass(frozen=True)
class DatasetRecord:
    text: str
    label: str
    source: str


class MLFirewallClassifier:
    def __init__(
        self,
        *,
        model_path: Path | None = None,
        report_path: Path | None = None,
        dataset_path: Path | None = None,
        model_name: str | None = None,
        batch_size: int | None = None,
        local_files_only: bool | None = None,
        encoder: SentenceTransformerEncoder | None = None,
    ) -> None:
        settings = get_settings()
        self.model_path = model_path or settings.ml_model_path
        self.report_path = report_path or settings.ml_training_report_path
        self.dataset_path = dataset_path or settings.ml_dataset_path
        self.model_name = model_name or settings.semantic_model_name
        self.batch_size = batch_size or settings.retrieval_batch_size
        self.local_files_only = (
            settings.semantic_local_files_only if local_files_only is None else local_files_only
        )
        self.encoder = encoder or SentenceTransformerEncoder(
            self.model_name,
            batch_size=self.batch_size,
            local_files_only=self.local_files_only,
        )
        self._bundle: dict[str, Any] | None = None

    def _load_bundle(self) -> dict[str, Any]:
        if self._bundle is not None:
            return self._bundle

        if not self.model_path.exists():
            raise RuntimeError(
                f"ML firewall model not found at `{self.model_path}`. "
                "Train it with `python -m app.ml_firewall train` first."
            )

        self._bundle = joblib.load(self.model_path)
        return self._bundle

    def load_dataset(self, dataset_path: Path | None = None) -> list[DatasetRecord]:
        path = dataset_path or self.dataset_path
        records: list[DatasetRecord] = []

        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            label = payload["label"].strip().lower()
            if label not in VALID_LABELS:
                raise ValueError(f"Unsupported label `{label}` in dataset.")
            records.append(
                DatasetRecord(
                    text=payload["text"].strip(),
                    label=label,
                    source=payload.get("source", "unspecified"),
                )
            )

        if not records:
            raise RuntimeError(f"No training records found in `{path}`.")

        return records

    def train(
        self,
        *,
        dataset_path: Path | None = None,
        model_path: Path | None = None,
        report_path: Path | None = None,
        test_size: float = 0.25,
        random_state: int = 42,
    ) -> dict[str, Any]:
        active_dataset_path = dataset_path or self.dataset_path
        active_model_path = model_path or self.model_path
        active_report_path = report_path or self.report_path
        records = self.load_dataset(active_dataset_path)

        texts = [record.text for record in records]
        labels = [record.label for record in records]
        embeddings = self.encoder.encode(texts)

        x_train, x_test, y_train, y_test = train_test_split(
            embeddings,
            labels,
            test_size=test_size,
            random_state=random_state,
            stratify=labels,
        )

        classifier = LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            solver="lbfgs",
        )
        classifier.fit(x_train, y_train)

        predictions = classifier.predict(x_test)
        report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
        metrics = {
            "accuracy": float(accuracy_score(y_test, predictions)),
            "classification_report": report,
            "labels": list(classifier.classes_),
            "dataset_size": len(records),
            "test_size": test_size,
            "embedding_model": self.model_name,
            "feature_dimensions": int(embeddings.shape[1]),
        }

        bundle = {
            "classifier": classifier,
            "labels": list(classifier.classes_),
            "model_name": self.model_name,
            "batch_size": self.batch_size,
            "local_files_only": self.local_files_only,
        }

        active_model_path.parent.mkdir(parents=True, exist_ok=True)
        active_report_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(bundle, active_model_path)
        active_report_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        self._bundle = bundle
        return metrics

    def inspect(self, text: str) -> dict[str, object]:
        normalized_text = " ".join(text.split())
        if not normalized_text:
            return {
                "label": "safe",
                "score": 0.0,
                "confidence": 1.0,
                "probabilities": {label: 0.0 for label in VALID_LABELS},
            }

        bundle = self._load_bundle()
        classifier: LogisticRegression = bundle["classifier"]
        probabilities = classifier.predict_proba(self.encoder.encode([normalized_text]))[0]
        labels = list(classifier.classes_)
        probability_map = {
            label: float(probabilities[index])
            for index, label in enumerate(labels)
        }

        predicted_label = max(probability_map, key=probability_map.get)
        confidence = max(probability_map.values())
        settings = get_settings()
        if predicted_label == "malicious" and confidence < settings.ml_classifier_min_confidence:
            predicted_label = "suspicious"
        elif predicted_label == "suspicious" and confidence < (settings.ml_classifier_min_confidence - 0.10):
            predicted_label = "safe"
        ml_score = float(
            probability_map.get("malicious", 0.0) +
            (0.5 * probability_map.get("suspicious", 0.0))
        )

        return {
            "label": predicted_label,
            "score": min(1.0, ml_score),
            "confidence": float(confidence),
            "probabilities": probability_map,
        }


_default_classifier: MLFirewallClassifier | None = None


def get_ml_classifier() -> MLFirewallClassifier:
    global _default_classifier

    if _default_classifier is None:
        _default_classifier = MLFirewallClassifier()

    return _default_classifier


def reset_ml_classifier() -> None:
    global _default_classifier
    _default_classifier = None


def ml_check(
    text: str,
    classifier: MLFirewallClassifier | None = None,
) -> dict[str, object]:
    active_classifier = classifier or get_ml_classifier()
    return active_classifier.inspect(text)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train the ML firewall classifier.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    train_parser = subparsers.add_parser("train", help="Train the ML firewall classifier.")
    train_parser.add_argument("--dataset", type=Path, default=None)
    train_parser.add_argument("--model-path", type=Path, default=None)
    train_parser.add_argument("--report-path", type=Path, default=None)
    train_parser.add_argument("--test-size", type=float, default=0.25)
    train_parser.add_argument("--random-state", type=int, default=42)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)
    classifier = MLFirewallClassifier()

    if args.command == "train":
        result = classifier.train(
            dataset_path=args.dataset,
            model_path=args.model_path,
            report_path=args.report_path,
            test_size=args.test_size,
            random_state=args.random_state,
        )
        print(json.dumps(result, indent=2))
        return 0

    parser.error(f"Unsupported command: {args.command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
