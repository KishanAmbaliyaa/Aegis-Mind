from flask import Flask, request, jsonify
from dotenv import load_dotenv
import os
from threat_intel import enrich_ip
from llm_analyzer import generate_triage_report
from notifier import send_notification

# Load environment variables
load_dotenv()

app = Flask(__name__)

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    try:
        # 1. Receive JSON payload from SIEM
        alert_data = request.json
        if not alert_data:
            return jsonify({'error': 'Invalid JSON payload'}), 400
            
        source_ip = alert_data.get('source_ip')
        if not source_ip:
            return jsonify({'error': 'Missing source_ip in alert data'}), 400
            
        # 2. Enrich with Threat Intel
        print(f"[*] Received alert for IP: {source_ip}. Enriching...")
        intel_data = enrich_ip(source_ip)
        
        # 3. Analyze with LLM
        print("[*] Threat Intel received. Analyzing with LLM...")
        report = generate_triage_report(alert_data, intel_data)
        
        # 4. Send Notification
        print("[*] Analysis complete. Sending notification...")
        send_notification(report)
        
        return jsonify({'status': 'success', 'message': 'Alert processed successfully'}), 200
        
    except Exception as e:
        print(f"[!] Error processing alert: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
