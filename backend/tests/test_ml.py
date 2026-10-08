import pytest
import os
from backend.app.ml.feature_extractor import extract_url_features, compute_entropy
from backend.app.ml.inference import predict_phishing_probability, load_model

pytestmark = pytest.mark.skip_db_init

def test_compute_entropy():
    assert compute_entropy("") == 0.0
    assert compute_entropy("aaaa") == 0.0
    assert compute_entropy("ab") > 0.0

def test_extract_url_features():
    url = "https://login.secure-apple-id.com.xyz/account/signin?id=123"
    feats = extract_url_features(url)
    
    assert isinstance(feats, dict)
    assert len(feats) == 12
    assert feats["https_status"] == 1
    assert feats["suspicious_tld"] == 1
    assert feats["has_ip"] == 0
    assert feats["url_length"] == len(url)
    assert "subdomain_count" in feats
    assert "dot_count" in feats
    assert "hyphen_count" in feats
    assert "digit_ratio" in feats

def test_extract_url_features_ip():
    url = "http://192.168.1.1/login"
    feats = extract_url_features(url)
    assert feats["has_ip"] == 1
    assert feats["https_status"] == 0

def test_inference_prediction():
    phishing_url = "http://login.secure-apple-id.com.xyz/account/signin"
    benign_url = "https://www.google.com"
    
    p_score = predict_phishing_probability(phishing_url)
    b_score = predict_phishing_probability(benign_url)
    
    assert isinstance(p_score, float)
    assert isinstance(b_score, float)
    assert 0.0 <= p_score <= 1.0
    assert 0.0 <= b_score <= 1.0
    # Phishing URL should have higher predicted probability than benign URL
    assert p_score > b_score

def test_model_artifact_exists():
    current_dir = os.path.dirname(__file__)
    model_path = os.path.join(current_dir, "..", "app", "ml", "phishing_xgb_v1.pkl")
    assert os.path.exists(model_path)
