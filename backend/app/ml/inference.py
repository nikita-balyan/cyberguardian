#inference.py
import json
import logging
import os

import joblib
import pandas as pd

from .feature_extractor import FEATURE_ORDER, extract_url_features, host_only_url

logger = logging.getLogger(__name__)

_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(_DIR, "phishing_xgb_v1.pkl")
META_PATH = os.path.join(_DIR, "phishing_xgb_v1.meta.json")

_MODEL_CACHE = None
_MODEL_TRIED = False
_META_CACHE = None


def load_meta() -> dict:
    """Training settings saved next to the model (host_only, neutralized_features...)."""
    global _META_CACHE
    if _META_CACHE is None:
        try:
            with open(META_PATH, encoding="utf-8") as f:
                _META_CACHE = json.load(f)
        except (OSError, ValueError):
            _META_CACHE = {}
    return _META_CACHE


def load_model():
    global _MODEL_CACHE, _MODEL_TRIED
    if _MODEL_CACHE is not None or _MODEL_TRIED:
        return _MODEL_CACHE
    _MODEL_TRIED = True
    if os.path.exists(MODEL_PATH):
        try:
            _MODEL_CACHE = joblib.load(MODEL_PATH)
        except Exception:
            logger.exception("Failed to load ML model from %s", MODEL_PATH)
    return _MODEL_CACHE


def uses_host_only() -> bool:
    """True if the saved model was trained with --host-only."""
    return bool(load_meta().get("host_only", False))


def predict_phishing_probability(url: str) -> float:
    """
    Returns a phishing probability between 0.0 and 1.0.
    If the model was trained host-only, the URL is reduced to its hostname first,
    exactly as in training. Falls back to a simple heuristic if the model is unavailable.
    """
    model = load_model()
    meta = load_meta()

    if model is not None:
        try:
            target = (host_only_url(url) or url) if uses_host_only() else url
            features = extract_url_features(target)
            row = {name: features[name] for name in FEATURE_ORDER}
            for name in meta.get("neutralized_features", []):
                row[name] = 0  # same neutralization as training
            proba = model.predict_proba(pd.DataFrame([row])[FEATURE_ORDER])[0][1]
            return float(proba)
        except Exception:
            logger.exception("Model prediction failed, using heuristic fallback")

    # Deterministic heuristic fallback if the model is unavailable
    features = extract_url_features(url)
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
