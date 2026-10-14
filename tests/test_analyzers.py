"""Unit tests for PhishGuard AI detection functions, heuristics, and reporting."""

import unittest
from src.email_analyzer import extract_email_indicators
from src.url_analyzer import extract_url_features, extract_url_heuristic_indicators, calculate_shannon_entropy
from src.ml_engine import predict_email, predict_url, load_evaluation_metrics
from src.ai_explainer import generate_threat_explanation
from src.report_generator import generate_security_report


class TestEmailAnalyzer(unittest.TestCase):
    """Test email heuristic extraction and indicator analysis."""

    def test_phishing_email_indicators(self):
        subject = "URGENT: Your account will be suspended in 24 hours"
        body = "Dear customer, unauthorized activity detected. Verify your password immediately by clicking here: http://192.168.1.1/login"
        
        result = extract_email_indicators(subject, body)
        self.assertGreater(result["total_indicators"], 0)
        self.assertGreaterEqual(result["high_severity_count"], 1)
        
        categories = [ind["category"] for ind in result["indicators"]]
        self.assertIn("Psychological Urgency", categories)
        self.assertIn("Credential Harvesting", categories)

    def test_legitimate_email_indicators(self):
        subject = "Team Sprint Planning - Thursday 10am"
        body = "Hi Alex, please find the agenda for our sprint retro attached. Let me know if you need to add any items."
        
        result = extract_email_indicators(subject, body)
        self.assertEqual(result["high_severity_count"], 0)


class TestURLAnalyzer(unittest.TestCase):
    """Test URL feature extraction, entropy, and heuristic indicators."""

    def test_raw_ip_url(self):
        url = "http://192.168.1.100/admin/login.php"
        features = extract_url_features(url)
        self.assertEqual(features["is_ip_hostname"], 1)
        self.assertEqual(features["uses_https"], 0)

        heuristics = extract_url_heuristic_indicators(url)
        names = [ind["name"] for ind in heuristics["indicators"]]
        self.assertIn("Direct IP Address Hostname", names)

    def test_at_symbol_spoofing(self):
        url = "http://bankofamerica.com@malicious-harvesting.xyz/auth"
        features = extract_url_features(url)
        self.assertEqual(features["has_at_symbol"], 1)

        heuristics = extract_url_heuristic_indicators(url)
        names = [ind["name"] for ind in heuristics["indicators"]]
        self.assertIn("Presence of '@' Symbol", names)

    def test_shannon_entropy(self):
        low_entropy = calculate_shannon_entropy("google")
        high_entropy = calculate_shannon_entropy("x8k29qmz10p4a")
        self.assertGreater(high_entropy, low_entropy)

    def test_legitimate_https_url(self):
        url = "https://github.com/scikit-learn/scikit-learn"
        features = extract_url_features(url)
        self.assertEqual(features["uses_https"], 1)
        self.assertEqual(features["is_ip_hostname"], 0)


class TestMLEngine(unittest.TestCase):
    """Test machine learning prediction pipelines and probabilities."""

    def test_email_prediction_structure(self):
        subject = "Action Required: Reset your corporate password"
        body = "Immediate action required: your password will expire today. Update credentials immediately."
        result = predict_email(subject, body)

        self.assertIn(result["predicted_class"], ["Phishing", "Legitimate"])
        self.assertGreaterEqual(result["phishing_probability"], 0.0)
        self.assertLessEqual(result["phishing_probability"], 1.0)
        self.assertIsInstance(result["top_features"], list)

    def test_url_prediction_structure(self):
        url = "http://45.33.32.156/secure/paypal-verification/index.html"
        result = predict_url(url)

        self.assertIn(result["predicted_class"], ["Phishing", "Legitimate"])
        self.assertGreaterEqual(result["phishing_probability"], 0.0)
        self.assertLessEqual(result["phishing_probability"], 1.0)

    def test_evaluation_metrics_loaded(self):
        metrics = load_evaluation_metrics()
        self.assertIn("email_model", metrics)
        self.assertIn("url_model", metrics)
        self.assertIn("accuracy", metrics["email_model"])
        self.assertIn("accuracy", metrics["url_model"])


class TestExplainerAndReports(unittest.TestCase):
    """Test AI explainer fallback and report generation."""

    def test_fallback_explanation_without_key(self):
        ml_result = {"predicted_class": "Phishing", "phishing_probability": 0.88, "legitimate_probability": 0.12}
        indicators = [{"category": "Urgency", "name": "Coercion", "severity": "HIGH", "description": "Immediate action"}]
        
        explanation = generate_threat_explanation(
            target_type="Email",
            target_content="Urgent verify password",
            ml_result=ml_result,
            indicators=indicators,
        )
        self.assertIn("explanation", explanation)
        self.assertGreater(len(explanation["recommendations"]), 0)

    def test_security_report_generation(self):
        ml_result = {"predicted_class": "Phishing", "phishing_probability": 0.92, "legitimate_probability": 0.08, "model_type": "TF-IDF + LR"}
        heuristic_data = {"indicators": [], "high_severity_count": 1, "medium_severity_count": 0, "low_severity_count": 0}
        ai_result = {"explanation": "Threat explanation", "recommendations": ["Do not click link"], "limitations_notice": "Advisory notice", "source": "Rule Engine"}
        
        report = generate_security_report(
            target_type="Email",
            target_identifier="Urgent wire transfer",
            ml_result=ml_result,
            heuristic_data=heuristic_data,
            ai_result=ai_result,
        )
        self.assertIn("PHISHGUARD AI - SECURITY INCIDENT REPORT", report)
        self.assertIn("EXECUTIVE THREAT VERDICT", report)
        self.assertIn("RECOMMENDED ACTIONS", report)


if __name__ == "__main__":
    unittest.main()
