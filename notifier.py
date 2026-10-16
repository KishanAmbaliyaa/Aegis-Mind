import os
import json
import logging
import requests
from typing import Dict, Any, Union, Optional
from config import settings
from models import TriageReport, SeverityEnum

logger = logging.getLogger("AegisMind.Notifier")

SEVERITY_COLORS_DISCORD = {
    SeverityEnum.CRITICAL.value: 15158332,  # Crimson Red
    SeverityEnum.HIGH.value: 15105570,      # Amber Orange
    SeverityEnum.MEDIUM.value: 15844367,    # Gold Yellow
    SeverityEnum.LOW.value: 3066993         # Forest Green
}


def _build_discord_payload(
    report: TriageReport,
    incident_uuid: str,
    source_ip: str,
    intel_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Generates a rich, interactive Discord Embed card for SOC analysts."""
    color = SEVERITY_COLORS_DISCORD.get(report.severity.value, 10197915)
    
    asn_info = f"{intel_data.get('as_owner', 'Unknown')} ({intel_data.get('country', '??')})"
    vt_votes = f"{intel_data.get('malicious_votes', 0)}/{intel_data.get('total_votes', 0)} engines flagged"
    
    embed = {
        "title": f"🚨 Aegis-Mind SOC Alert Triage [{report.severity.value}]",
        "description": report.attack_vector_summary,
        "color": color,
        "fields": [
            {
                "name": "🎯 Target / Indicator",
                "value": f"`{source_ip}`\n**ASN:** {asn_info}\n**VT Score:** {vt_votes}",
                "inline": True
            },
            {
                "name": "🏷️ MITRE ATT&CK Mapping",
                "value": f"**Tactic:** {report.mitre_tactic}\n**Technique:** `{report.mitre_technique_id}` - {report.mitre_technique_name}",
                "inline": True
            },
            {
                "name": "📊 Confidence & Noise Filter",
                "value": f"**Confidence:** `{int(report.confidence_score * 100)}%`\n**False Positive:** `{'Yes (Noise)' if report.is_false_positive else 'No (Active Threat)'}`",
                "inline": True
            },
            {
                "name": "🛡️ Recommended Containment",
                "value": f"```{report.recommended_containment}```",
                "inline": False
            },
            {
                "name": "⚡ Quick SOAR Containment Trigger",
                "value": f"Execute via API: `POST /api/action/contain` with UUID `{incident_uuid}`",
                "inline": False
            }
        ],
        "footer": {
            "text": f"Incident UUID: {incident_uuid} • Aegis-Mind Autonomous SOAR"
        }
    }
    return {"embeds": [embed]}


def _build_slack_payload(
    report: TriageReport,
    incident_uuid: str,
    source_ip: str,
    intel_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Generates a structured Slack Block Kit message payload."""
    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 SOC Alert Triage: [{report.severity.value}] Incident",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Attack Summary:*\n{report.attack_vector_summary}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Indicator:* `{source_ip}`"},
                    {"type": "mrkdwn", "text": f"*MITRE:* `{report.mitre_technique_id}` ({report.mitre_technique_name})"},
                    {"type": "mrkdwn", "text": f"*Confidence:* {int(report.confidence_score * 100)}%"},
                    {"type": "mrkdwn", "text": f"*Auto-Containment:* {'Recommended' if report.auto_containment_recommended else 'Analyst Review'}"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Containment Action:*\n```{report.recommended_containment}```"
                }
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Incident ID: `{incident_uuid}` | Aegis-Mind v2.0"}
                ]
            }
        ]
    }


def send_notification(
    report: Union[TriageReport, Dict[str, Any]],
    incident_uuid: str = "local-sim",
    source_ip: str = "Unknown",
    intel_data: Optional[Dict[str, Any]] = None
) -> None:
    """Dispatches rich interactive alert notifications to Discord or Slack."""
    if intel_data is None:
        intel_data = {}

    # Normalize to TriageReport if dict
    if isinstance(report, dict):
        report = TriageReport.model_validate(report)

    slack_url = settings.SLACK_WEBHOOK_URL
    discord_url = settings.DISCORD_WEBHOOK_URL

    dispatched = False

    # Send Discord Embed
    if discord_url and discord_url != "your_discord_webhook_url_here":
        payload = _build_discord_payload(report, incident_uuid, source_ip, intel_data)
        try:
            res = requests.post(discord_url, json=payload, timeout=8)
            if res.status_code in (200, 204):
                logger.info("[*] Rich notification successfully dispatched to Discord.")
                dispatched = True
            else:
                logger.error(f"[!] Discord dispatch failed: HTTP {res.status_code} - {res.text}")
        except Exception as e:
            logger.error(f"[!] Exception dispatching to Discord: {e}")

    # Send Slack Block Kit
    if slack_url and slack_url != "your_slack_webhook_url_here":
        payload = _build_slack_payload(report, incident_uuid, source_ip, intel_data)
        try:
            res = requests.post(slack_url, json=payload, timeout=8)
            if res.status_code == 200:
                logger.info("[*] Block Kit notification successfully dispatched to Slack.")
                dispatched = True
            else:
                logger.error(f"[!] Slack dispatch failed: HTTP {res.status_code} - {res.text}")
        except Exception as e:
            logger.error(f"[!] Exception dispatching to Slack: {e}")

    # Fallback simulation logging
    if not dispatched:
        print("\n" + "=" * 60)
        print("  🛡️  AEGIS-MIND SOAR NOTIFICATION (SIMULATION CONSOLE) 🛡️")
        print("=" * 60)
        print(f"Incident UUID : {incident_uuid}")
        print(f"Indicator     : {source_ip}")
        print(f"Severity      : {report.severity.value} (Confidence: {int(report.confidence_score * 100)}%)")
        print(f"MITRE ATT&CK  : [{report.mitre_technique_id}] {report.mitre_technique_name} ({report.mitre_tactic})")
        print(f"Summary       : {report.attack_vector_summary}")
        print(f"Containment   : {report.recommended_containment}")
        print(f"Auto-Block    : {'YES' if report.auto_containment_recommended else 'NO (Requires Analyst Approval)'}")
        print("=" * 60 + "\n")
