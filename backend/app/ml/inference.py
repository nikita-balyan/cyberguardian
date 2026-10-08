import os
import joblib
import pandas as pd
from backend.app.ml.feature_extractor import extract_url_features

_MODEL_CACHE = None

def load_model():
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE
    
    current_dir = os.path.dirname(__file__)
    model_path = os.path.join(current_dir, "phishing_xgb_v1.pkl")
    
    if os.path.exists(model_path):
        try:
            _MODEL_CACHE = joblib.load(model_path)
        except Exception as e:
            print(f"Warning: Failed to load ML model from {model_path}: {e}")
            _MODEL_CACHE = None
    return _MODEL_CACHE

def predict_phishing_probability(url: str) -> float:
    """
    Loads phishing_xgb_v1.pkl and returns a risk score between 0.0 and 1.0.
    Falls back gracefully if the model artifact is missing or fails to load.
    """
    model = load_model()
    features = extract_url_features(url)
    df_features = pd.DataFrame([features])
    
    if model is not None:
        try:
            proba = model.predict_proba(df_features)[0][1]
            return float(proba)
        except Exception as e:
            print(f"Warning: Model prediction failed ({e}), using heuristic fallback.")
            
    # Deterministic heuristic fallback if model is unavailable
    score = 0.1
    if features["suspicious_tld"] == 1:
        score += 0.4
    if features["has_ip"] == 1:
        score += 0.3
    if features["subdomain_count"] > 1:
        score += 0.2
    if features["https_status"] == 0:
        score += 0.1
    return float(min(1.0, max(0.0, score)))
