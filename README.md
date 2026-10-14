# 🛡️ PhishGuard AI - Cyber Threat Intelligence Suite

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-FF4B4B.svg)](https://streamlit.io/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-F7931E.svg)](https://scikit-learn.org/)
[![Plotly](https://img.shields.io/badge/Plotly-5.20%2B-3F4F75.svg)](https://plotly.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**PhishGuard AI** is an AI-powered cybersecurity threat intelligence application engineered for Artificial Intelligence (AI) coursework and incident response demonstrations. It analyzes suspicious emails and URLs using a dual-engine architecture: genuine **scikit-learn** machine learning models coupled with deterministic **heuristic threat indicator** extraction, supported by **Google Gemini API** for contextual threat explanation and incident response guidance.

---

## 🚀 Key Features

1. **Security Operations Center (SOC) Dashboard**:
   - Live session telemetry: tracks total scans, confirmed phishing detections, and harmless traffic.
   - Dynamic Plotly donut charts and scan confidence telemetry.
   - Operates on real in-memory session data.

2. **Email Phishing Analyzer**:
   - Scikit-learn TF-IDF Vectorizer + Logistic Regression Classifier providing genuine $P(\text{Phishing})$ model posterior probabilities.
   - Feature attribution displaying top indicative n-grams driving the classification.
   - Rule-based heuristic indicators detecting psychological urgency, credential theft hooks, executive impersonation, and suspicious links.
   - One-click pre-loaded test samples for instant demonstrations.

3. **URL Safety & Structural Analyzer**:
   - Scikit-learn Random Forest Classifier trained on 16 lexical and structural features.
   - Feature inspection: URL length, raw IP hostname detection, HTTPS encryption check, subdomain depth, and Shannon Entropy (detecting algorithmic domain generation / DGA).
   - Non-intrusive static inspection: **Never automatically fetches, opens sockets to, or visits submitted URLs**.

4. **Gemini AI Threat Explanation & Fallback Engine**:
   - Contextual threat reasoning explaining attack vectors and recommending safe next steps.
   - **Prompt Injection Hardening**: All untrusted emails and URLs are isolated within strict `<UNTRUSTED_CONTENT>` boundary delimiters.
   - **Zero-Failure Architecture**: If the Gemini API key is missing or offline, PhishGuard AI seamlessly switches to a deterministic expert rule-based advisor without interrupting the user.

5. **Transparency & Model Performance**:
   - Holdout test set metrics: Accuracy, Precision, Recall, F1 Score, and Confusion Matrix heatmaps.
   - Gini feature importance bar chart for decision tree classifiers.
   - Standardized, copyable Markdown incident response security reports.

---

## 🧠 System Architecture: How AI is Implemented

PhishGuard AI cleanly separates statistical learning, generative reasoning, and deterministic rules:

| Component | Engine / Technology | Purpose |
| :--- | :--- | :--- |
| **Email ML Classifier** | `TfidfVectorizer` + `LogisticRegression` | Computes mathematical $P(\text{Phishing})$ posterior probabilities and word/n-gram weights. |
| **URL ML Classifier** | `StandardScaler` + `RandomForestClassifier` | Evaluates 16 numerical/lexical features using an ensemble of 100 decision trees. |
| **Contextual Explainer** | Google Gemini (`gemini-2.5-flash`) via `google-genai` | Synthesizes threat reasoning, attack tactics, and prioritized incident remediation steps. |
| **Heuristic Indicators** | Regular expressions and string parsing | Deterministic checks (urgency language, credential harvesting, brand impersonation, raw IP, high-risk TLDs). |
| **Offline Fallback** | Deterministic expert template engine | Provides immediate structured security guidance when Gemini API key is not configured. |

---

## 📁 Project Structure

```text
PhishGuard-AI/
├── .env.example              # Template for Gemini API key configuration
├── .gitignore                 # Excludes .env, secrets, venv, joblib models, and caches
├── requirements.txt           # Python package dependencies
├── README.md                  # Complete documentation and setup guide
├── train_models.py            # Machine learning training and evaluation pipeline
├── app.py                     # Streamlit web application entry point
├── src/
│   ├── __init__.py
│   ├── config.py              # Environment variables and path constants
│   ├── styles.py              # Cyberpunk dark navy theme CSS and badge components
│   ├── email_analyzer.py      # Email heuristic pattern detection engine
│   ├── url_analyzer.py        # URL feature extraction & Shannon entropy engine
│   ├── ml_engine.py           # Model loading, inference, and feature attribution
│   ├── ai_explainer.py        # Gemini API integration with prompt injection defenses
│   └── report_generator.py    # Standardized security incident report generator
├── models/
│   ├── .gitkeep               # Preserves models directory in Git
│   ├── metrics.json           # Evaluation metrics on independent test splits
│   ├── email_model.joblib     # (Auto-generated by train_models.py; ignored by Git)
│   └── url_model.joblib       # (Auto-generated by train_models.py; ignored by Git)
├── data/
│   └── .gitkeep               # Preserves data directory in Git
└── tests/
    ├── __init__.py
    └── test_analyzers.py      # Comprehensive unit tests for detection functions
```

---

## 💻 Windows Setup & Quick-Start Guide

Follow these steps in **PowerShell** or **Command Prompt** on Windows:

### 1. Clone or Download the Project

```powershell
git clone <your-repository-url>
cd PhishGuard-AI
```

*(If you received a `.zip` archive, extract it and navigate into the `PhishGuard-AI` folder).*

---

### 2. Create and Activate a Virtual Environment

Creating an isolated virtual environment ensures clean dependency management:

**In PowerShell:**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

> **PowerShell Script Execution Policy Note:**  
> If PowerShell gives an error saying *“running scripts is disabled on this system”*, run this command in your current session:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .\venv\Scripts\Activate.ps1
> ```

**In Command Prompt (cmd.exe):**
```cmd
python -m venv venv
.\venv\Scripts\activate.bat
```

---

### 3. Install Dependencies

Upgrade `pip` and install all necessary packages:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

### 4. Configure Google Gemini API Key (Optional)

PhishGuard AI works **100% offline out-of-the-box** using built-in rule-based threat explanations! To optionally enable Google Gemini AI-generated incident response narratives:

1. Create a `.env` file by copying `.env.example`:
   ```powershell
   # In PowerShell:
   Copy-Item .env.example .env

   # In Command Prompt:
   copy .env.example .env
   ```
2. Open `.env` in any text editor (Notepad, VS Code) and add your free Google AI Studio key:
   ```env
   GEMINI_API_KEY=your_actual_gemini_api_key_here
   ```
   *(You can obtain a free Gemini API key from [Google AI Studio](https://aistudio.google.com/app/apikey)).*

> **Security Guarantee:** The `.env` file is strictly ignored by `.gitignore` so your API key will never be accidentally committed to Git. You can also paste an API key directly into the application's **Settings** tab during runtime.

---

### 5. Train / Generate Machine Learning Models

Binary `.joblib` model files are deliberately excluded from Git to keep the repository lightweight. You can generate them by running the training pipeline:

```powershell
python train_models.py
```

This will:
- Train the TF-IDF + Logistic Regression email classifier.
- Train the Standard Scaler + Random Forest URL classifier.
- Evaluate both models on independent holdout test splits.
- Save `email_model.joblib`, `url_model.joblib`, and `metrics.json` into the `models/` directory.

*(Note: Even if you skip this step, PhishGuard AI is smart enough to auto-detect missing models and train them automatically on first startup).*

---

### 6. Run Unit Tests

Verify that feature extraction, heuristic indicators, Shannon entropy, ML models, and security reports are functioning properly:

```powershell
python -m unittest tests/test_analyzers.py
```

Expected output:
```text
...........
----------------------------------------------------------------------
Ran 11 tests in 2.033s

OK
```

---

### 7. Launch the Streamlit Web Application

Start the web application:

```powershell
python -m streamlit run app.py
```

Streamlit will launch local server and automatically open the application in your default web browser at:
```text
http://localhost:8501
```

---

## 🛡️ Academic & Security Disclaimers

- **Calibrated Probabilities**: The probabilities displayed in PhishGuard AI are genuine machine learning posterior probabilities ($P(\text{Phishing})$) derived from scikit-learn models. Heuristic flags are strictly presented as rule checklists, never disguised as model probabilities.
- **Static vs. Dynamic Analysis**: URL inspection is strictly static and lexical. PhishGuard AI does not fetch remote websites, execute JavaScript, or download payloads.
- **Advisory Status**: Automated threat detection tools are intended to assist human triage. Borderline or critical security alerts should always be corroborated by your organization's IT Security Operations Center (SOC).

---

## 👨‍💻 License & Author
* **Coursework Project**: Built for Artificial Intelligence (AI) coursework.
* **License**: Open-source under the [MIT License](LICENSE).
