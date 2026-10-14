"""Model training pipeline for PhishGuard AI.

Trains real scikit-learn classifiers for both Email and URL threat detection.
Evaluates on independent test splits and saves trained models + evaluation metrics.
"""

import json
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
import joblib

from src.config import EMAIL_MODEL_PATH, URL_MODEL_PATH, METRICS_PATH, MODELS_DIR
from src.url_analyzer import extract_url_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ==============================================================================
# 1. CURATED EMAIL DATASET
# ==============================================================================
EMAIL_DATA = [
    # --- PHISHING EXAMPLES (Label: 1) ---
    {
        "text": "URGENT: Your Office 365 Account Will Be Suspended. Your corporate email account is scheduled for immediate deactivation within 24 hours. Please log in here to verify your credentials immediately to avoid disruption.",
        "label": 1
    },
    {
        "text": "Security Alert: Unauthorized access detected from Moscow, Russia. If this was not you, reset your password now by visiting our secure verification link: http://192.168.1.45/verify-account",
        "label": 1
    },
    {
        "text": "Internal Revenue Service: You have an unclaimed tax refund of $1,420.50 pending. To process your deposit, update your banking details and enter your Social Security Number.",
        "label": 1
    },
    {
        "text": "PayPal: Account Limited. Dear customer, we observed unusual activity on your card. Please confirm your identity and billing information immediately or your account will be permanently closed.",
        "label": 1
    },
    {
        "text": "Payroll Update - Direct Deposit Failure. Immediate action required. Your latest salary payout could not be processed due to invalid routing numbers. Re-enter your bank credentials below.",
        "label": 1
    },
    {
        "text": "CEO Urgent Request: Are you at your desk? I am in a board meeting and need you to urgently purchase $500 Apple gift cards for a client presentation. Send the redemption codes to my personal email right away.",
        "label": 1
    },
    {
        "text": "DHL Express: Package Delivery Exception. Your parcel #DH891278 cannot be delivered due to an unpaid customs fee of $2.99. Click the tracking link to pay now before package return.",
        "label": 1
    },
    {
        "text": "Netflix Membership Suspended: We could not authorize your monthly billing cycle. Update your payment method within 12 hours to maintain uninterrupted streaming service.",
        "label": 1
    },
    {
        "text": "IT Helpdesk: Scheduled System Upgrade. All employees must re-validate their active directory password before 5:00 PM today. Unverified user accounts will lose network access.",
        "label": 1
    },
    {
        "text": "Meta Security Team: Your Facebook Business Page has violated copyright policies and is flagged for deletion. Submit an appeal through our support portal within 24 hours.",
        "label": 1
    },
    {
        "text": "Wire Transfer Notice: Please review the attached remittance invoice INV-9023.html and confirm receipt of funds immediately.",
        "label": 1
    },
    {
        "text": "DocuSign: Action Required. You received an encrypted financial agreement from CFO. Sign in to view and sign this time-sensitive document.",
        "label": 1
    },
    {
        "text": "Bank of America Fraud Department: Suspicious charge of $948.00 at BestBuy. If you did not make this transaction, call our automated helpline or click here to reverse charges.",
        "label": 1
    },
    {
        "text": "Final Notice: Your Cloud Storage is 99% full. Incoming emails will be bounced starting tomorrow unless you upgrade and verify your credit card information.",
        "label": 1
    },
    {
        "text": "Cryptocurrency Alert: MetaMask wallet seed phrase synchronization error. Confirm your 12-word recovery phrase on the decentralized server to secure your tokens.",
        "label": 1
    },

    # --- LEGITIMATE EXAMPLES (Label: 0) ---
    {
        "text": "Weekly Engineering Sync Agenda. Hi team, please find attached the meeting notes for tomorrow's standup. We will cover the sprint backlog and deployment milestones. See you at 10 AM.",
        "label": 0
    },
    {
        "text": "Google Docs: Sarah shared 'Q3 Financial Review' with you. Hi Alex, take a look at the spreadsheet when you have a moment and leave comments on slide 4.",
        "label": 0
    },
    {
        "text": "GitHub: [phishguard/ai] Pull Request #14 merged. Feature/auth-refactor has been merged into main by dev-lead. All automated CI test pipelines passed successfully.",
        "label": 0
    },
    {
        "text": "Your Amazon Order Confirmation #114-9821-209. Thank you for your order. We will notify you once your items ship. Expected delivery date: Thursday, Oct 15.",
        "label": 0
    },
    {
        "text": "Python Software Foundation Newsletter: Issue #128. Welcome to this month's digest covering Python 3.13 release features, PyCon keynote speakers, and community tutorials.",
        "label": 0
    },
    {
        "text": "Delta Air Lines: Flight Confirmation for Trip to Boston. Your e-ticket and itinerary are confirmed. You can check in 24 hours prior to departure via the Delta mobile app.",
        "label": 0
    },
    {
        "text": "University Registrar: Fall Semester Final Exam Schedule. Dear students, the final examination timetable is now published on the official student portal. Best wishes on your studies.",
        "label": 0
    },
    {
        "text": "Slack: You were mentioned in #devops by Marcus: 'The staging database migration finished without issues, logs look healthy.'",
        "label": 0
    },
    {
        "text": "Customer Support Ticket #4591 Resolved. Hello, we have resolved your query regarding API rate limits. Let us know if you need any additional assistance.",
        "label": 0
    },
    {
        "text": "Quarterly All-Hands Meeting Recording. Hello everyone, thank you for attending today's company all-hands. The slides and recording have been uploaded to our internal wiki.",
        "label": 0
    },
    {
        "text": "Spotify Wrapped: Your Year in Music is Ready! Check out your top artists, most played genres, and favorite playlists from the past year inside the app.",
        "label": 0
    },
    {
        "text": "Coffee catchup tomorrow? Hey Princy, let me know if you are free around 3 PM for a quick coffee break to discuss the AI project presentation.",
        "label": 0
    },
    {
        "text": "LinkedIn: 3 people viewed your profile this week. See who viewed your profile and connect with colleagues in your network.",
        "label": 0
    },
    {
        "text": "Uber Receipt: Your ride with driver David on Sunday evening. Trip total: $18.45. Thanks for riding with Uber.",
        "label": 0
    },
    {
        "text": "Library Book Return Reminder: The item 'Artificial Intelligence: A Modern Approach' is due in 3 days. You can renew online through the library catalog.",
        "label": 0
    },
]


# ==============================================================================
# 2. CURATED URL DATASET
# ==============================================================================
URL_DATA = [
    # --- PHISHING URLS (Label: 1) ---
    {"url": "http://192.168.1.105/admin/login.php?session=credential_steal", "label": 1},
    {"url": "http://45.33.32.156/secure/paypal-verification/index.html", "label": 1},
    {"url": "http://office365-security-portal.account-update.xyz/login.aspx", "label": 1},
    {"url": "http://apple-id-verify.support-device-lock.top/auth/signin", "label": 1},
    {"url": "http://paypal.com.verify-billing-info.club/webapps/login", "label": 1},
    {"url": "http://netflix-billing-update-failure.click/account/login", "label": 1},
    {"url": "http://secure-login-chase-bank.fraud-alert.work/auth", "label": 1},
    {"url": "http://user:password@legitbank.com.hacker-server.live/login", "label": 1},
    {"url": "http://microsoft-outlook-web-access.pw/owa/auth/logon.aspx", "label": 1},
    {"url": "http://amazon-account-revalidation-order.buzz/signin", "label": 1},
    {"url": "http://bit.ly/3xFakeBankLoginObfuscatedShortLink", "label": 1},
    {"url": "http://218.92.0.14:8080/banking/authenticate.html", "label": 1},
    {"url": "http://wellsfargo.com-online-secure-banking-portal.rest/verify", "label": 1},
    {"url": "http://internal-hr-payroll-compensation-update.gq/login", "label": 1},
    {"url": "http://google-drive-shared-encrypted-invoice.tk/view", "label": 1},

    # --- LEGITIMATE URLS (Label: 0) ---
    {"url": "https://www.google.com/search?q=cybersecurity+defense", "label": 0},
    {"url": "https://github.com/microsoft/vscode/releases", "label": 0},
    {"url": "https://docs.python.org/3/library/urllib.parse.html", "label": 0},
    {"url": "https://en.wikipedia.org/wiki/Phishing", "label": 0},
    {"url": "https://stackoverflow.com/questions/tagged/machine-learning", "label": 0},
    {"url": "https://aws.amazon.com/console/", "label": 0},
    {"url": "https://www.nytimes.com/section/technology", "label": 0},
    {"url": "https://developer.mozilla.org/en-US/docs/Web/HTTP", "label": 0},
    {"url": "https://streamlit.io/components", "label": 0},
    {"url": "https://scikit-learn.org/stable/modules/linear_model.html", "label": 0},
    {"url": "https://login.live.com/login.srf", "label": 0},
    {"url": "https://mail.google.com/mail/u/0/#inbox", "label": 0},
    {"url": "https://portal.azure.com/#home", "label": 0},
    {"url": "https://www.paypal.com/signin", "label": 0},
    {"url": "https://www.apple.com/shop/buy-mac", "label": 0},
]


def train_email_classifier():
    """Train TF-IDF + LogisticRegression classifier for emails."""
    logging.info("Training Email Phishing Classifier...")
    df = pd.DataFrame(EMAIL_DATA)
    
    # Train / test split (test_size=0.33, stratified, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.33, random_state=42, stratify=df["label"]
    )
    
    # Text vectorizer
    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        max_features=2500,
        sublinear_tf=True,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    # Logistic Regression Classifier (calibrated probability estimates via sigmoid)
    clf = LogisticRegression(C=1.5, class_weight="balanced", random_state=42, max_iter=1000)
    clf.fit(X_train_vec, y_train)
    
    # Evaluate on holdout test set
    y_pred = clf.predict(X_test_vec)
    y_proba = clf.predict_proba(X_test_vec)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    logging.info(f"Email Classifier Test Accuracy: {acc:.4f}, F1: {f1:.4f}")
    
    # Save model artifact
    model_bundle = {
        "vectorizer": vectorizer,
        "classifier": clf,
        "target_names": ["Legitimate", "Phishing"],
        "model_type": "TF-IDF + LogisticRegression",
    }
    joblib.dump(model_bundle, EMAIL_MODEL_PATH)
    logging.info(f"Saved email model to {EMAIL_MODEL_PATH}")
    
    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "confusion_matrix": cm,
        "test_sample_count": len(y_test),
        "train_sample_count": len(y_train),
    }


def train_url_classifier():
    """Train feature-based Random Forest classifier for URLs."""
    logging.info("Training URL Safety Classifier...")
    df = pd.DataFrame(URL_DATA)
    
    # Feature extraction for each URL
    feature_rows = []
    for url in df["url"]:
        feats = extract_url_features(url)
        # Exclude metadata strings
        filtered = {k: v for k, v in feats.items() if k not in ("hostname", "clean_url")}
        feature_rows.append(filtered)
        
    feat_df = pd.DataFrame(feature_rows)
    feature_names = list(feat_df.columns)
    
    # Train / test split (test_size=0.33, stratified, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(
        feat_df.values, df["label"], test_size=0.33, random_state=42, stratify=df["label"]
    )
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    clf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    clf.fit(X_train_scaled, y_train)
    
    y_pred = clf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    logging.info(f"URL Classifier Test Accuracy: {acc:.4f}, F1: {f1:.4f}")
    
    # Save model artifact
    model_bundle = {
        "scaler": scaler,
        "feature_names": feature_names,
        "classifier": clf,
        "target_names": ["Legitimate", "Phishing"],
        "model_type": "StandardScaler + RandomForestClassifier",
    }
    joblib.dump(model_bundle, URL_MODEL_PATH)
    logging.info(f"Saved URL model to {URL_MODEL_PATH}")
    
    # Feature importance
    importances = dict(zip(feature_names, [round(float(i), 4) for i in clf.feature_importances_]))
    
    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "confusion_matrix": cm,
        "feature_importances": importances,
        "test_sample_count": len(y_test),
        "train_sample_count": len(y_train),
    }


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    email_metrics = train_email_classifier()
    url_metrics = train_url_classifier()
    
    full_metrics = {
        "email_model": email_metrics,
        "url_model": url_metrics,
        "metadata": {
            "evaluation_split": "Holdout Test Set (33%)",
            "evaluation_method": "Stratified Test Split",
            "training_date": "2026-10-12",
        }
    }
    
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(full_metrics, f, indent=2)
    logging.info(f"Saved test evaluation metrics to {METRICS_PATH}")
    print("\n--- Training & Evaluation Complete ---")
    print("Email Model Test Metrics:", email_metrics)
    print("URL Model Test Metrics:", url_metrics)


if __name__ == "__main__":
    main()
