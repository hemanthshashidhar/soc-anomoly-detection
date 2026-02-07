import subprocess
import json
from pathlib import Path
from datetime import datetime

# ======================================================
# PATHS
# ======================================================

BASE_DIR = Path(__file__).resolve().parent.parent
ALERT_FILE = BASE_DIR / "data" / "live_alerts.json"

print("[+] Starting REALTIME SSH WRITER")
print("[+] Writing to:", ALERT_FILE)

# ======================================================
# ENSURE FILE EXISTS
# ======================================================

if not ALERT_FILE.exists():
    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_FILE, "w") as f:
        json.dump([], f)

# ======================================================
# JOURNALCTL STREAM (PARROT CONFIRMED)
# ======================================================

cmd = [
    "journalctl",
    "-u", "ssh",
    "-f",
    "--no-pager"
]

process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# ======================================================
# MAIN LOOP
# ======================================================

for line in process.stdout:
    if not line:
        continue

    line = line.strip()
    print("[RAW SSH]", line)

    if "Failed password for" in line:
        parts = line.split()

        try:
            if "invalid user" in line:
                user = parts[parts.index("user") + 1]
            else:
                user = parts[parts.index("for") + 1]

            ip = parts[parts.index("from") + 1]
        except Exception as e:
            print("[PARSE ERROR]", e)
            continue

        alert = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user,
            "ip": ip,
            "attack_type": "SSH_FAILED_LOGIN",
            "alert_level": "HIGH",
            "source": "ssh",
            "active_attack": 1,
            "risk_score": 0.85,
            "reasons": [f"SSH failed login attempt from {ip}", "Potential brute force attack"],
            "narrative": f"SSH security alert: Failed login attempt for user '{user}' from IP {ip}. This could indicate a brute force attack or unauthorized access attempt."
        }

        # Append to JSON
        with open(ALERT_FILE, "r") as f:
            data = json.load(f)

        data.append(alert)

        with open(ALERT_FILE, "w") as f:
            json.dump(data, f, indent=2)

        print("🚨 SSH ALERT WRITTEN:", alert)

