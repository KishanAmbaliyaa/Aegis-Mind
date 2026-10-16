import json
import logging
from typing import Dict, Any
from google import genai
from config import settings
from models import TriageReport, SeverityEnum

logger = logging.getLogger("AegisMind.LLMAnalyzer")


def _generate_fallback_report(alert_data: Dict[str, Any], intel_data: Dict[str, Any], reason: str) -> TriageReport:
    """Creates a deterministic fallback triage report when LLM is unavailable or fails."""
    rule_desc = alert_data.get("rule", {}).get("description", "Potential Security Incident")
    src_ip = alert_data.get("source_ip", "Unknown")
    malicious_votes = intel_data.get("malicious_votes", 0)

    # Heuristic severity calculation
    if malicious_votes >= 10:
        severity = SeverityEnum.CRITICAL
        confidence = 0.90
        auto_contain = True
    elif malicious_votes >= 3:
        severity = SeverityEnum.HIGH
        confidence = 0.75
        auto_contain = False
    else:
        severity = SeverityEnum.MEDIUM
        confidence = 0.50
        auto_contain = False

    return TriageReport(
        severity=severity,
        confidence_score=confidence,
        is_false_positive=False,
        attack_vector_summary=f"Automated fallback assessment for alert on {src_ip} ({rule_desc}). Threat intel indicated {malicious_votes} malicious reports.",
        mitre_tactic="Initial Access / Credential Access",
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        recommended_containment=f"Apply temporary rate-limiting or boundary firewall block on IP {src_ip}.",
        auto_containment_recommended=auto_contain,
        analyst_guidance=f"LLM generation bypassed ({reason}). Verify source IP reputation on secondary threat databases."
    )


def generate_triage_report(alert_data: Dict[str, Any], intel_data: Dict[str, Any]) -> TriageReport:
    """
    Leverages Google Gemini with Structured Output (Pydantic Schema)
    to perform deep SOC alert analysis, MITRE ATT&CK mapping, and containment advice.
    """
    api_key = settings.GEMINI_API_KEY
    if not api_key or api_key == "your_gemini_api_key_here":
        logger.warning("[!] Gemini API key not configured. Using deterministic fallback report.")
        return _generate_fallback_report(alert_data, intel_data, "Missing or dummy GEMINI_API_KEY")

    client = genai.Client(api_key=api_key)

    prompt = f"""You are a Principal Security Operations Center (SOC) Analyst and Threat Hunter.
Carefully review the incoming raw security alert log alongside external threat intelligence telemetry.

RAW SIEM ALERT:
{json.dumps(alert_data, indent=2)}

EXTERNAL THREAT INTEL TELEMETRY:
{json.dumps(intel_data, indent=2)}

ANALYSIS OBJECTIVES:
1. Determine true severity level (LOW, MEDIUM, HIGH, CRITICAL) and provide a confidence score (0.0 to 1.0).
2. Assess if this is a false positive or benign scanner noise (e.g. Shodan, Censys, internal vulnerability scanners).
3. Map the attack behavior accurately to the official MITRE ATT&CK Matrix (Tactic, Technique ID like T1110, and Technique Name).
4. Provide a succinct 2-3 sentence executive attack vector summary.
5. Provide specific, immediate, firewall or endpoint containment instructions.
6. Set auto_containment_recommended to True ONLY if confidence is >= 0.85 and severity is HIGH or CRITICAL.
7. Offer Tier 2/3 analyst follow-up guidance.

Return your assessment adhering strictly to the structured JSON schema.
"""

    try:
        # Use Gemini 3.5 Flash / 2.5 Flash with structured JSON schema
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=prompt,
            config={
                "response_mime_type": "application/json",
                "response_schema": TriageReport,
                "temperature": 0.2  # Low temperature for deterministic security reasoning
            }
        )

        raw_json = response.text.strip()
        report = TriageReport.model_validate_json(raw_json)
        logger.info(f"[+] Structured triage completed: Severity={report.severity}, Technique={report.mitre_technique_id}")
        return report

    except Exception as e:
        logger.error(f"[!] Error calling Gemini API or validating structured response: {e}")
        return _generate_fallback_report(alert_data, intel_data, f"Gemini API error: {str(e)}")
