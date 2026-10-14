"""Email feature extraction and heuristic threat indicator analysis."""

import re
from typing import Dict, List, Any


# Regular expressions for URL and email extraction
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'`()]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>"\'`]*)?',
    re.IGNORECASE,
)
IP_IN_URL_REGEX = re.compile(
    r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>"\'`]*)?',
    re.IGNORECASE,
)

# Indicator Pattern Dictionaries
URGENCY_PATTERNS = [
    (r"\b(immediate(?:ly)?\s+action\s+required|urgent\s+action\s+required)\b", "Immediate action requirement"),
    (r"\b(account(?:\s+will\s+be)?\s+(?:suspended|terminated|deactivated|locked))\b", "Account suspension or termination threat"),
    (r"\b(within\s+\d+\s+(?:hours?|minutes?|days?)|in\s+\d+\s+hours?)\b", "Tight artificial deadline"),
    (r"\b(failure\s+to\s+comply|final\s+notice|last\s+warning)\b", "Coercive penalty language"),
    (r"\b(unauthorized\s+(?:access|transaction|activity)\s+detected)\b", "Panic-inducing security alert"),
]

CREDENTIAL_PATTERNS = [
    (r"\b(verify\s+your\s+(?:password|identity|account|credentials|pin))\b", "Credential verification prompt"),
    (r"\b(update\s+your\s+(?:billing|payment|security|banking)\s+information)\b", "Financial/payment update request"),
    (r"\b(reset\s+your\s+password\s+(?:here|now|immediately))\b", "Urgent password reset call-to-action"),
    (r"\b(log\s*in\s+(?:here|below|now)\s+to\s+(?:confirm|verify|restore))\b", "Direct link credential harvesting invitation"),
    (r"\b(enter\s+your\s+(?:ssn|social\s+security|credit\s+card|passcode))\b", "Sensitive personal identifier solicitation"),
]

IMPERSONATION_PATTERNS = [
    (r"\b(microsoft|office\s*365|google\s+security|paypal|apple\s+support|netflix|amazon\s+fraud)\b", "High-profile tech/financial brand claim"),
    (r"\b(it\s+support\s+desk|system\s+administrator|helpdesk\s+team|hr\s+department)\b", "Internal IT or corporate department impersonation"),
    (r"\b(federal\s+reserve|internal\s+revenue\s+service|tax\s+refund|customs\s+department)\b", "Government or tax authority impersonation"),
]

GENERIC_GREETING_PATTERNS = [
    (r"\b(dear\s+(?:customer|user|client|valued\s+member|account\s+holder|sir/madam))\b", "Generic anonymous greeting"),
    (r"^(attention|dear\s+recipient)[:!]", "Impersonal mass-mailing salutation"),
]

ATTACHMENT_SUSPICION_PATTERNS = [
    (r"\b(?:attached|attachment)\s+(?:invoice|statement|remittance|receipt|document)\b", "Invoice/Financial attachment hook"),
    (r"\b\.(?:html|htm|exe|scr|iso|vbs|zip|rar|js|bat)\b", "High-risk executable or script attachment extension"),
]


def extract_email_indicators(subject: str, body: str) -> Dict[str, Any]:
    """
    Extract rule-based heuristic security indicators from an email.
    
    Returns structured details of suspicious patterns matched.
    Note: These are transparent rule indicators, NOT machine learning probabilities.
    """
    full_text = f"{subject}\n{body}".strip()
    lowered_text = full_text.lower()
    
    indicators: List[Dict[str, Any]] = []

    # 1. Check Urgency & Coercion (High Severity)
    urgency_matches = []
    for pattern, label in URGENCY_PATTERNS:
        found = re.findall(pattern, lowered_text, re.IGNORECASE)
        if found:
            urgency_matches.append(label)
    if urgency_matches:
        indicators.append({
            "category": "Psychological Urgency",
            "name": "Artificial Urgency & Threat of Loss",
            "severity": "HIGH",
            "description": f"Uses psychological coercion to pressure immediate response: {', '.join(urgency_matches)}.",
            "matches": urgency_matches,
        })

    # 2. Check Credential & Financial Harvesting (High Severity)
    credential_matches = []
    for pattern, label in CREDENTIAL_PATTERNS:
        found = re.findall(pattern, lowered_text, re.IGNORECASE)
        if found:
            credential_matches.append(label)
    if credential_matches:
        indicators.append({
            "category": "Credential Harvesting",
            "name": "Solicitation of Credentials or Sensitive Data",
            "severity": "HIGH",
            "description": f"Attempts to redirect recipient to disclose private data: {', '.join(credential_matches)}.",
            "matches": credential_matches,
        })

    # 3. Check Brand / Executive Impersonation (Medium Severity)
    impersonation_matches = []
    for pattern, label in IMPERSONATION_PATTERNS:
        found = re.findall(pattern, lowered_text, re.IGNORECASE)
        if found:
            impersonation_matches.append(label)
    if impersonation_matches:
        indicators.append({
            "category": "Brand Impersonation",
            "name": "Authority / Well-Known Entity Claim",
            "severity": "MEDIUM",
            "description": f"References high-value target identities: {', '.join(set(impersonation_matches))}.",
            "matches": list(set(impersonation_matches)),
        })

    # 4. Check Generic Salutations (Low Severity)
    greeting_matches = []
    for pattern, label in GENERIC_GREETING_PATTERNS:
        found = re.findall(pattern, lowered_text, re.IGNORECASE)
        if found:
            greeting_matches.append(label)
    if greeting_matches:
        indicators.append({
            "category": "Greeting Anomalies",
            "name": "Impersonal or Generic Salutation",
            "severity": "LOW",
            "description": "Legitimate enterprise communications usually address you by specific first or last name.",
            "matches": greeting_matches,
        })

    # 5. Extract URLs from body and check for suspicious traits
    extracted_urls = URL_REGEX.findall(body)
    ip_urls = IP_IN_URL_REGEX.findall(body)
    
    if ip_urls:
        indicators.append({
            "category": "Suspicious Link",
            "name": "Direct IP Address Hostname in Email Link",
            "severity": "HIGH",
            "description": f"Contains link pointing directly to raw numerical IP instead of domain name: {', '.join(ip_urls[:3])}.",
            "matches": ip_urls,
        })
    elif extracted_urls:
        shorteners = [u for u in extracted_urls if any(s in u.lower() for s in ["bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy"])]
        if shorteners:
            indicators.append({
                "category": "Obfuscated Link",
                "name": "URL Shortener Detected in Email Body",
                "severity": "MEDIUM",
                "description": f"URL shorteners hide the final destination of target links: {', '.join(shorteners[:2])}.",
                "matches": shorteners,
            })

    # 6. Check Attachment / Execution Lures (Medium Severity)
    attachment_matches = []
    for pattern, label in ATTACHMENT_SUSPICION_PATTERNS:
        found = re.findall(pattern, lowered_text, re.IGNORECASE)
        if found:
            attachment_matches.append(label)
    if attachment_matches:
        indicators.append({
            "category": "Attachment Risk",
            "name": "Suspicious Attachment or Invoice Call-to-Action",
            "severity": "MEDIUM",
            "description": f"Email prompts opening attachments or documents: {', '.join(attachment_matches)}.",
            "matches": attachment_matches,
        })

    # Calculate summary indicator metrics
    high_count = sum(1 for ind in indicators if ind["severity"] == "HIGH")
    med_count = sum(1 for ind in indicators if ind["severity"] == "MEDIUM")
    low_count = sum(1 for ind in indicators if ind["severity"] == "LOW")
    
    return {
        "indicators": indicators,
        "total_indicators": len(indicators),
        "high_severity_count": high_count,
        "medium_severity_count": med_count,
        "low_severity_count": low_count,
        "extracted_urls": extracted_urls,
        "char_count": len(full_text),
        "word_count": len(full_text.split()),
    }
