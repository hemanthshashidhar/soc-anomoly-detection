import subprocess
import json
from datetime import datetime
from pathlib import Path

# ======================================================
# PATHS
# ======================================================

BASE_DIR = Path(__file__).resolve().parent.parent
ALERT_FILE = BASE_DIR / "data" / "realtime_ssh_alerts.json"

print("[+] Real-time SSH monitor started")
print("[+] Listening to ssh.service")
print("[+] Writing alerts to:", ALERT_FILE)

# ======================================================
# ENSURE ALERT FILE EXISTS
# ======================================================

if not ALERT_FILE.exists():
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
# ALERT WRITER
# ======================================================

def write_alert(alert):
    with open(ALERT_FILE, "r+") as f:
        data = json.load(f)
        data.append(alert)
        f.seek(0)
        json.dump(data, f, indent=2)

# ======================================================
# MONITOR LOOP
# ======================================================

for line in process.stdout:
    if not line:
        continue

    line = line.strip()
    print("[RAW]", line)

    # Failed SSH login
    if "Failed password for" in line:
        parts = line.split()

        try:
            if "invalid user" in line:
                user = parts[parts.index("user") + 1]
            else:
                user = parts[parts.index("for") + 1]

            ip = parts[parts.index("from") + 1]
        except Exception:
            continue

        alert = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user,
            "ip": ip,
            "attack_type": "SSH_FAILED_LOGIN",
            "alert_level": "HIGH",
            "source": "ssh"
        }

        write_alert(alert)
        print("🚨 SSH FAILED LOGIN ALERT WRITTEN")

    # Successful SSH login (optional, useful later)
    elif "Accepted password for" in line:
        parts = line.split()

        try:
            user = parts[parts.index("for") + 1]
            ip = parts[parts.index("from") + 1]
        except Exception:
            continue

        alert = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user,
            "ip": ip,
            "attack_type": "SSH_SUCCESS_LOGIN",
            "alert_level": "LOW",
            "source": "ssh"
        }

        write_alert(alert)
        print("✅ SSH SUCCESS LOGIN ALERT WRITTEN")
