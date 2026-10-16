import os
from google import genai
import json

def generate_triage_report(alert_data, intel_data):
    """
    Uses Gemini API to generate a succinct triage report based on the SIEM alert and Threat Intel.
    """
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key or api_key == 'your_gemini_api_key_here':
        print("[!] Gemini API key not configured. Returning mock report.")
        return "Mock report due to missing keys."
    # Configure the Gemini API client
    client = genai.Client(api_key=api_key)
    
    prompt = f"""You are an expert Senior SOC Analyst. Review the following raw security log and the attached external threat intelligence data.
RAW SIEM LOG:
{json.dumps(alert_data, indent=2)}
THREAT INTELLIGENCE DATA:
{json.dumps(intel_data, indent=2)}
Provide a highly concise, 3-sentence summary of the attack vector. Map the attack behavior to a specific MITRE ATT&CK tactic and technique ID. Finally, recommend an immediate, actionable containment step for the firewall administration team.
"""
    try:
        # Using Gemini 3.5 Flash (Fast and perfect for text tasks)
        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=prompt
        )
        return response.text.strip()
    except Exception as e:
        print(f"[!] Error calling Gemini API: {e}")
        return f"Automated analysis failed: {str(e)}"
