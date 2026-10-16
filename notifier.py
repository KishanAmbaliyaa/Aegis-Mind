import os
import requests
import json

def send_notification(report_text):
    """
    Sends the triage report to a Discord or Slack webhook.
    """
    slack_url = os.getenv('SLACK_WEBHOOK_URL')
    discord_url = os.getenv('DISCORD_WEBHOOK_URL')

    if slack_url and slack_url != 'your_slack_webhook_url_here':
        payload = {'text': f"🚨 **SOC Alert Triage Report** 🚨\n\n{report_text}"}
        try:
            requests.post(slack_url, json=payload)
            print("[*] Notification sent to Slack.")
        except Exception as e:
            print(f"[!] Failed to send Slack notification: {e}")
            
    elif discord_url and discord_url != 'your_discord_webhook_url_here':
        payload = {'content': f"🚨 **SOC Alert Triage Report** 🚨\n\n{report_text}"}
        try:
            requests.post(discord_url, json=payload)
            print("[*] Notification sent to Discord.")
        except Exception as e:
            print(f"[!] Failed to send Discord notification: {e}")
    else:
        print("[!] No webhook URL configured. Simulated Notification Output:")
        print("-" * 40)
        print(report_text)
        print("-" * 40)
