import os
import requests

def enrich_ip(ip_address):
    """
    Queries the VirusTotal API to get reputation data for an IP address.
    """
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key or api_key == 'your_virustotal_api_key_here':
        print("[!] VirusTotal API key not configured. Returning mock data.")
        return {
            "malicious_votes": 15,
            "total_votes": 88,
            "network": "192.168.0.0/16",
            "country": "Mock Country",
            "as_owner": "Mock AS Owner"
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json().get('data', {}).get('attributes', {})
        
        last_analysis = data.get('last_analysis_stats', {})
        
        return {
            "malicious_votes": last_analysis.get('malicious', 0),
            "total_votes": sum(last_analysis.values()),
            "network": data.get('network', 'Unknown'),
            "country": data.get('country', 'Unknown'),
            "as_owner": data.get('as_owner', 'Unknown')
        }
    except Exception as e:
        print(f"[!] Error calling VirusTotal API: {e}")
        return {"error": str(e)}
