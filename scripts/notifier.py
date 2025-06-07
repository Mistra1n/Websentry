# scripts/notifier.py
import requests
import json

class Notifier:
    def __init__(self):
        self.config = self._load_config()
    
    def _load_config(self):
        with open('config/notifications.json') as f:
            return json.load(f)

    def send_slack(self, message):
        payload = {"text": f"WebSentry Alert: {message}"}
        requests.post(
            self.config['slack_webhook'],
            json=payload,
            headers={'Content-Type': 'application/json'}
        )

    def send_discord(self, message):
        payload = {"content": f"🔔 WebSentry Alert: {message}"}
        requests.post(
            self.config['discord_webhook'],
            json=payload
        )
