# Aegis-Mind 🛡️🧠

**Aegis-Mind** is an autonomous AI-driven Security Operations Center (SOC) alert triage and threat intelligence enrichment system. It intercepts security events from SIEM tools (such as Wazuh, Splunk, or Elastic), automatically enriches attacker indicators with real-time threat intelligence (VirusTotal API), generates structured triage summaries and MITRE ATT&CK mappings using Google Gemini LLM, and dispatches actionable alerts directly to security team channels (Slack or Discord).

---

## 🚀 Key Features

- **Automated SIEM Alert Ingestion**: Webhook endpoint (`/api/alert`) ready to ingest JSON payloads from SIEM solutions and honeypots.
- **Threat Intelligence Enrichment**: Real-time IP reputation checks using the VirusTotal v3 API (malicious votes, network ownership, country of origin).
- **AI-Powered Triage & MITRE ATT&CK Mapping**: Leverages Google Gemini (`gemini-3.5-flash` via the official `google-genai` SDK) to produce concise attack summaries and recommended firewall containment actions.
- **Instant Team Notifications**: Sends formatted, high-priority triage alerts directly to Discord or Slack webhooks.
- **Built-in Alert Simulator**: Easily simulate real-world brute-force security incidents locally for testing and demonstration.

---

## 🏗️ Architecture & Workflow

```text
[ SIEM / Honeypot / Wazuh ]
            │  (JSON Alert Payload)
            ▼
    [ Flask Webhook Server ] (/api/alert)
            │
            ├──► [ VirusTotal API ] (Enrich Source IP Reputation)
            │
            ├──► [ Google Gemini LLM ] (Triage Analysis & MITRE Mapping)
            │
            ▼
[ Security Alert Dispatcher ]
            ├──► Slack Webhook
            └──► Discord Webhook
```

---

## 📋 Prerequisites

- **Python 3.10+**
- **VirusTotal API Key**: (Free community tier supported)
- **Google Gemini API Key**: [Google AI Studio](https://aistudio.google.com/)
- *(Optional)* Discord or Slack Incoming Webhook URL

---

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/KishanAmbaliyaa/Aegis-Mind.git
   cd Aegis-Mind
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   Copy the `.env.example` file to `.env`:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your actual API keys:
   ```env
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   GEMINI_API_KEY=your_gemini_api_key_here
   SLACK_WEBHOOK_URL=your_slack_webhook_url_here
   DISCORD_WEBHOOK_URL=your_discord_webhook_url_here
   ```

---

## 🏃 Running Aegis-Mind

### 1. Start the Triage Webhook Server
```bash
python app.py
```
The server will start listening on `http://0.0.0.0:5000`.

### 2. Simulate a Security Alert
In a separate terminal, trigger a simulated SSH brute-force attack event:
```bash
python simulate_alert.py
```

### 3. Observe the Triage Output
The console will log the alert intake, VirusTotal enrichment details, Gemini-generated analysis, and the notification dispatch:
```text
[*] Received alert for IP: 185.122.204.197. Enriching...
[*] Threat Intel received. Analyzing with LLM...
[*] Analysis complete. Sending notification...
[*] Notification sent to Discord.
```

---

## 📁 Project Structure

```text
Aegis-Mind/
├── app.py              # Flask webhook server for SIEM alert ingestion
├── threat_intel.py     # VirusTotal v3 IP enrichment module
├── llm_analyzer.py     # Google Gemini prompt engineering & triage generation
├── notifier.py         # Discord & Slack webhook alert dispatcher
├── simulate_alert.py   # Test suite simulating realistic SIEM brute-force alerts
├── requirements.txt    # Python dependencies
├── .env.example        # Template for required environment variables
├── .gitignore          # Git exclusion rules (protects credentials & cache)
├── LICENSE             # MIT License
└── README.md           # Project documentation
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
