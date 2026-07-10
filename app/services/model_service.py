import numbers

import joblib
import pandas as pd

from app.config import MODEL_PATH, logger
from app.schemas.traffic import FEATURE_COLUMNS


MODEL_NAME = "Random Forest IDS Pipeline"


def _plain(value):
    if hasattr(value, "item"):
        value = value.item()
    if isinstance(value, numbers.Integral):
        return int(value)
    if isinstance(value, numbers.Real):
        return float(value)
    return value


def _class_key(value):
    value = _plain(value)
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


class ModelService:
    def __init__(self):
        self.pipeline = None
        self.feature_columns: list[str] = []
        self.label_mapping: dict[int, str] = {}
        self.metrics: dict = {}

    @property
    def model(self):
        return self.pipeline

    @property
    def features(self):
        return self.feature_columns

    def load(self) -> None:
        if self.pipeline is not None:
            return
        try:
            bundle = joblib.load(MODEL_PATH)
            self._validate_bundle(bundle)
        except Exception:
            logger.exception("Failed to load model bundle from %s", MODEL_PATH)
            raise

        self.pipeline = bundle["pipeline"]
        self.feature_columns = list(bundle["feature_columns"])
        self.label_mapping = {
            _class_key(key): str(value)
            for key, value in bundle["label_mapping"].items()
        }
        self.metrics = dict(bundle.get("metrics") or {})
        logger.info("Loaded %s with %s features.", MODEL_NAME, len(self.feature_columns))

    def _validate_bundle(self, bundle) -> None:
        if not isinstance(bundle, dict):
            raise ValueError("model bundle must be a dict")
        missing = {"pipeline", "feature_columns", "label_mapping"} - set(bundle)
        if missing:
            raise ValueError(f"model bundle missing required keys: {sorted(missing)}")
        if not hasattr(bundle["pipeline"], "predict"):
            raise ValueError("model bundle pipeline does not support predict")
        if list(bundle["feature_columns"]) != FEATURE_COLUMNS:
            raise ValueError("model bundle feature_columns must match the 42 raw UNSW-NB15 fields")
        if not isinstance(bundle["label_mapping"], dict):
            raise ValueError("model bundle label_mapping must be a dict")

    def predict(self, record: dict) -> dict:
        return self.predict_many([record])[0]

    def predict_many(self, records: list[dict]) -> list[dict]:
        if self.pipeline is None:
            raise RuntimeError("model is not loaded")
        if not records:
            return []

        input_df = pd.DataFrame([
            {name: record[name] for name in self.feature_columns}
            for record in records
        ])
        raw_labels = [_class_key(label) for label in self.pipeline.predict(input_df)]
        proba_rows = [None] * len(raw_labels)
        classes = []
        if hasattr(self.pipeline, "predict_proba"):
            proba_rows = list(self.pipeline.predict_proba(input_df))
            classes = self._classes()

        results = []
        for raw_label, proba in zip(raw_labels, proba_rows):
            prediction_label = int(raw_label)
            prediction = self.label_mapping.get(raw_label, str(raw_label))
            probabilities = {}
            confidence = None
            if proba is not None and classes and len(classes) == len(proba):
                probabilities = {
                    self.label_mapping.get(_class_key(cls), str(_class_key(cls))): round(float(prob), 4)
                    for cls, prob in zip(classes, proba)
                }
                confidence = probabilities.get(prediction)

            results.append({
                "prediction": prediction,
                "prediction_label": prediction_label,
                "confidence": confidence,
                "probabilities": probabilities,
            })
        return results

    def _classes(self):
        if hasattr(self.pipeline, "classes_"):
            return list(self.pipeline.classes_)
        steps = getattr(self.pipeline, "steps", None)
        if steps:
            final_estimator = steps[-1][1]
            if hasattr(final_estimator, "classes_"):
                return list(final_estimator.classes_)
        return []

    def get_metadata(self):
        return {
            "model_name": MODEL_NAME,
            "feature_count": len(self.feature_columns),
            "feature_columns": self.feature_columns,
            "label_mapping": {str(key): value for key, value in self.label_mapping.items()},
            "metrics": {
                key: float(self.metrics.get(key, 0.0))
                for key in ("accuracy", "precision_attack", "recall_attack", "f1_score_attack")
            },
        }


model_service = ModelService()
