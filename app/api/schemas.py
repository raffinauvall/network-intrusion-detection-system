import math
from typing import Dict

from pydantic import BaseModel, ConfigDict, model_validator
from app.config import MAX_INSPECT_FEATURES


class InspectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    features: Dict[str, float]

    @model_validator(mode="after")
    def validate_feature_values(self):
        if len(self.features) > MAX_INSPECT_FEATURES:
            raise ValueError(f"Too many features: maximum is {MAX_INSPECT_FEATURES}")

        invalid = [
            name
            for name, value in self.features.items()
            if not math.isfinite(float(value))
        ]
        if invalid:
            raise ValueError(f"Feature values must be finite numbers: {', '.join(invalid)}")
        return self
