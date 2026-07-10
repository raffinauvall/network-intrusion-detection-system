from typing import Optional

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_name: str


class ModelInfoResponse(BaseModel):
    model_name: str
    feature_count: int
    feature_columns: list[str]
    label_mapping: dict[str, str]
    metrics: dict[str, float]


class PredictionResponse(BaseModel):
    prediction: str
    prediction_label: int
    confidence: Optional[float]
    probabilities: dict[str, float]
