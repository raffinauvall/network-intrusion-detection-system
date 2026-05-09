from pydantic import BaseModel
from typing import Dict

class InspectRequest(BaseModel):
    features: Dict[str, float]
