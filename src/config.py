"""Configuration and environment management for PhishGuard AI."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data"

# Ensure runtime directories exist
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Load environment variables from .env file
load_dotenv(PROJECT_ROOT / ".env")

# Gemini API configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL_NAME = "gemini-2.5-flash"

# Model paths
EMAIL_MODEL_PATH = MODELS_DIR / "email_model.joblib"
URL_MODEL_PATH = MODELS_DIR / "url_model.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"

# Cybersecurity UI Theme Constants
THEME = {
    "bg_dark": "#0B1120",
    "card_bg": "#111C35",
    "card_border": "#1E2E52",
    "accent_cyan": "#00E5FF",
    "accent_blue": "#3B82F6",
    "alert_danger": "#EF4444",
    "alert_warning": "#F59E0B",
    "alert_success": "#10B981",
    "text_main": "#F8FAFC",
    "text_muted": "#94A3B8",
}

# Risk Thresholds
THRESHOLD_HIGH = 0.70
THRESHOLD_MEDIUM = 0.40
