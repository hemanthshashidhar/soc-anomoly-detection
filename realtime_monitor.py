import subprocess
import re
import json
from datetime import datetime
from realtime_ai_detector import analyze_realtime_event

LIVE_ALERTS_FILE = "data/live_alerts.json"

print("[REALTIME] AI Live Monitor Started...\n")

process = subprocess.Popen(
    ["journalctl", "-f", "--no-pager"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

for line in process.stdout:
    if "Failed password" in line:

        user = "Unknown"
        invalid_match = re.search(r"invalid user\s*([a-zA-Z0-9_]+)", line)
        normal_match = re.search(r"user ([a-zA-Z0-9_]+)|user=([a-zA-Z0-9_]+)", line)

        if invalid_match:
            user = invalid_match.group(1)
        elif normal_match:
            user = normal_match.group(1) or normal_match.group(2)

        ip_match = re.search(r"from ([\da-fA-F\.:]+)", line)
        ip = ip_match.group(1) if ip_match else "Unknown"

        alert = analyze_realtime_event(user, ip)
        alert["timestamp"] = datetime.now().isoformat()
        alert["user"] = user
        alert["ip"] = ip
        alert["source"] = "ssh"  # CRITICAL: Add source field

        try:
            with open(LIVE_ALERTS_FILE, "r") as f:
                alerts = json.load(f)
        except:
            alerts = []

        alerts.append(alert)

        with open(LIVE_ALERTS_FILE, "w") as f:
            json.dump(alerts[-50:], f, indent=2)

        print("\n⚠️ LIVE AI ALERT")
        print("User:", user)
        print("IP:", ip)
        print("Attack:", alert["attack_type"])
