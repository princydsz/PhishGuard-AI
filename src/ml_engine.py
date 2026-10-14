"""Machine Learning inference engine for email and URL phishing classification."""

import json
import logging
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd
import joblib

from src.config import EMAIL_MODEL_PATH, URL_MODEL_PATH, METRICS_PATH
from src.url_analyzer import extract_url_features

logger = logging.getLogger(__name__)

# Cached model objects
_EMAIL_BUNDLE = None
_URL_BUNDLE = None


def load_email_model() -> Dict[str, Any]:
    """Load or cache the trained Email Classifier bundle."""
    global _EMAIL_BUNDLE
    if _EMAIL_BUNDLE is not None:
        return _EMAIL_BUNDLE
    
    if not EMAIL_MODEL_PATH.exists():
        logger.warning(f"Email model not found at {EMAIL_MODEL_PATH}. Training models now...")
        import train_models
        train_models.main()
        
    _EMAIL_BUNDLE = joblib.load(EMAIL_MODEL_PATH)
    return _EMAIL_BUNDLE


def load_url_model() -> Dict[str, Any]:
    """Load or cache the trained URL Classifier bundle."""
    global _URL_BUNDLE
    if _URL_BUNDLE is not None:
        return _URL_BUNDLE
    
    if not URL_MODEL_PATH.exists():
        logger.warning(f"URL model not found at {URL_MODEL_PATH}. Training models now...")
        import train_models
        train_models.main()
        
    _URL_BUNDLE = joblib.load(URL_MODEL_PATH)
    return _URL_BUNDLE


def predict_email(subject: str, body: str) -> Dict[str, Any]:
    """
    Perform genuine ML inference on an email.
    
    Returns:
        dict containing:
            - predicted_class: "Phishing" or "Legitimate"
            - phishing_probability: float (0.0 to 1.0) derived strictly from model
            - legitimate_probability: float (0.0 to 1.0) derived strictly from model
            - model_type: str
            - top_features: list of words/n-grams that influenced this classification
    """
    bundle = load_email_model()
    vectorizer = bundle["vectorizer"]
    classifier = bundle["classifier"]
    
    full_text = f"{subject} {body}".strip()
    if not full_text:
        return {
            "predicted_class": "Uncertain",
            "phishing_probability": 0.50,
            "legitimate_probability": 0.50,
            "model_type": bundle.get("model_type", "TF-IDF + LogisticRegression"),
            "top_features": [],
        }
    
    # Vectorize input text
    X_vec = vectorizer.transform([full_text])
    
    # Model derived posterior probabilities
    probas = classifier.predict_proba(X_vec)[0]
    legit_prob = float(probas[0])
    phish_prob = float(probas[1])
    
    predicted_class = "Phishing" if phish_prob >= 0.50 else "Legitimate"
    
    # Feature attribution: examine non-zero TF-IDF features multiplied by coefficients
    feature_names = vectorizer.get_feature_names_out()
    coefs = classifier.coef_[0]
    row = X_vec.tocoo()
    
    influential = []
    for col, val in zip(row.col, row.data):
        word = feature_names[col]
        weight = coefs[col] * val
        influential.append((word, float(weight)))
        
    # Sort: positive weights push toward Phishing, negative weights toward Legitimate
    influential.sort(key=lambda x: abs(x[1]), reverse=True)
    top_features = [
        {"term": item[0], "impact": "Phishing Signal" if item[1] > 0 else "Legitimate Signal", "weight": round(item[1], 3)}
        for item in influential[:6]
    ]
    
    return {
        "predicted_class": predicted_class,
        "phishing_probability": round(phish_prob, 4),
        "legitimate_probability": round(legit_prob, 4),
        "model_type": bundle.get("model_type", "TF-IDF + LogisticRegression"),
        "top_features": top_features,
    }


def predict_url(raw_url: str) -> Dict[str, Any]:
    """
    Perform genuine ML inference on a URL using trained structural/lexical classifier.
    
    Returns:
        dict containing:
            - predicted_class: "Phishing" or "Legitimate"
            - phishing_probability: float (0.0 to 1.0) derived strictly from model
            - legitimate_probability: float (0.0 to 1.0) derived strictly from model
            - model_type: str
            - raw_features: extracted feature dictionary
    """
    bundle = load_url_model()
    scaler = bundle["scaler"]
    feature_names = bundle["feature_names"]
    classifier = bundle["classifier"]
    
    # Extract structural and lexical features
    feats = extract_url_features(raw_url)
    
    # Assemble feature vector in matching order
    vector = [feats.get(fn, 0) for fn in feature_names]
    vector_array = np.array([vector])
    
    # Scale and predict
    scaled_vector = scaler.transform(vector_array)
    probas = classifier.predict_proba(scaled_vector)[0]
    legit_prob = float(probas[0])
    phish_prob = float(probas[1])
    
    predicted_class = "Phishing" if phish_prob >= 0.50 else "Legitimate"
    
    return {
        "predicted_class": predicted_class,
        "phishing_probability": round(phish_prob, 4),
        "legitimate_probability": round(legit_prob, 4),
        "model_type": bundle.get("model_type", "StandardScaler + RandomForestClassifier"),
        "raw_features": feats,
    }


def load_evaluation_metrics() -> Dict[str, Any]:
    """Load evaluation metrics computed during model training on independent test splits."""
    if not METRICS_PATH.exists():
        import train_models
        train_models.main()
        
    with open(METRICS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
