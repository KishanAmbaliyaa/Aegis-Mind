import requests
import time
import json

# Simulated payload mimicking a Wazuh/Splunk alert for a brute force attack
simulated_payload = {
    "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    "rule": {
        "level": 10,
        "description": "SSHD brute force trying to get access to the system.",
        "id": "5712",
        "mitre": {
            "id": ["T1110"],
            "tactic": ["Credential Access"],
            "technique": ["Brute Force"]
        }
    },
    "agent": {
        "id": "001",
        "name": "linux-honeypot-01"
    },
    "manager": {
        "name": "wazuh-manager"
    },
    "source_ip": "185.122.204.197",  # Known malicious IP for testing
    "location": "/var/log/auth.log",
    "decoder": {
        "name": "sshd"
    },
    "data": {
        "srcuser": "root",
        "srcport": "44312"
    }
}

def send_simulation():
    url = "http://127.0.0.1:5000/api/alert"
    print(f"[*] Sending simulated SIEM alert to {url}...")
    
    try:
        response = requests.post(url, json=simulated_payload)
        print(f"[*] Response Status: {response.status_code}")
        print(f"[*] Response Body: {json.dumps(response.json(), indent=2)}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection Error: Is the Flask webhook server running? (python app.py)")

if __name__ == '__main__':
    send_simulation()
