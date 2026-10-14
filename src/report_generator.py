"""Security incident report generator for PhishGuard AI."""

from datetime import datetime
import uuid
from typing import Dict, Any, List


def generate_security_report(
    target_type: str,
    target_identifier: str,
    ml_result: Dict[str, Any],
    heuristic_data: Dict[str, Any],
    ai_result: Dict[str, Any],
) -> str:
    """
    Generate a standardized, copyable Markdown incident response report.
    """
    incident_id = f"PG-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    pred_class = ml_result.get("predicted_class", "Uncertain").upper()
    phish_prob = ml_result.get("phishing_probability", 0.0)
    legit_prob = ml_result.get("legitimate_probability", 0.0)
    model_type = ml_result.get("model_type", "Machine Learning Classifier")
    
    indicators: List[Dict[str, Any]] = heuristic_data.get("indicators", [])
    high_count = heuristic_data.get("high_severity_count", 0)
    med_count = heuristic_data.get("medium_severity_count", 0)
    low_count = heuristic_data.get("low_severity_count", 0)
    
    explanation = ai_result.get("explanation", "No advisory generated.")
    ai_source = ai_result.get("source", "PhishGuard Analysis")
    recommendations = ai_result.get("recommendations", [])
    limitations = ai_result.get("limitations_notice", "")

    ind_lines = []
    if indicators:
        for idx, ind in enumerate(indicators, 1):
            ind_lines.append(f"{idx}. [{ind['severity']}] {ind['name']}: {ind['description']}")
    else:
        ind_lines.append("No heuristic threat flags detected.")
    indicators_formatted = "\n".join(ind_lines)

    recs_formatted = "\n".join([f"- {r}" for r in recommendations])

    report = f"""================================================================================
                    PHISHGUARD AI - SECURITY INCIDENT REPORT
================================================================================
INCIDENT ID:       {incident_id}
GENERATED AT:      {timestamp}
TARGET CLASSIFIED: {target_type.upper()}
EVALUATED TARGET:  {target_identifier}
--------------------------------------------------------------------------------

[1] EXECUTIVE THREAT VERDICT
----------------------------
* Primary Verdict:          {pred_class}
* ML Phishing Probability:  {phish_prob:.2%}
* ML Legitimate Confidence: {legit_prob:.2%}
* Classification Engine:    {model_type}
* Heuristic Flags:          {high_count} HIGH | {med_count} MEDIUM | {low_count} LOW

[2] DETECTED SECURITY INDICATORS & EVIDENCE
-------------------------------------------
{indicators_formatted}

[3] THREAT EXPLANATION ({ai_source})
----------------------------------------------------------------
{explanation}

[4] RECOMMENDED ACTIONS & INCIDENT REMEDIATION
----------------------------------------------
{recs_formatted}

[5] LIMITATIONS & ADVISORY NOTICE
---------------------------------
{limitations}
Note: Probabilities are model-derived estimations. Uncertain or borderline results
should always be corroborated with your organization's IT / SOC department.
================================================================================
"""
    return report
