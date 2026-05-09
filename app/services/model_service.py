import joblib
import pandas as pd
import numpy as np
from app.config import logger, MODEL_PATH

class ModelService:
    def __init__(self):
        self.model = None
        self.features = []
        self._load_model()

    def _load_model(self):
        try:
            data = joblib.load(MODEL_PATH)
            self.model = data["model"]
            self.model.verbose = 0
            self.model.n_jobs = 1
            self.features = data["features"]
            logger.info(f"Model loaded successfully with {len(self.features)} features.")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise e

    def predict(self, feature_dict: dict):
        vector = [feature_dict.get(f, 0.0) for f in self.features]
        df = pd.DataFrame([vector], columns=self.features)
        
        pred = self.model.predict(df)[0]
        proba = self.model.predict_proba(df)[0]
        confidence = float(max(proba))
        
        return int(pred), confidence, proba

    def get_metadata(self):
        importances = self.model.feature_importances_
        top_indices = np.argsort(importances)[::-1][:20]
        top_features = [
            {"name": self.features[i], "importance": round(float(importances[i]), 6)}
            for i in top_indices
        ]
        return {
            "total_features": len(self.features),
            "feature_names": self.features,
            "model_type": "RandomForestClassifier",
            "n_estimators": self.model.n_estimators,
            "top_20_features": top_features,
        }

# Singleton instance
model_service = ModelService()
