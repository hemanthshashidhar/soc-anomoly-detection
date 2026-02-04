import time
import json
from pathlib import Path
from datetime import datetime
import subprocess
from collections import defaultdict

# ============================================================
# PATHS & CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
POLICY_FILE = BASE_DIR / "profiles" / "resource_policies.json"
LIVE_ALERTS_FILE = BASE_DIR / "data" / "live_alerts.json"
AUDIT_LOG = "/var/log/audit/audit.log"

ALERT_COOLDOWN_SECONDS = 30  # prevent duplicate spam

print("[+] Realtime auditd monitor started")

# ============================================================
# LOAD RESOURCE ACCESS POLICIES
# ============================================================

with open(POLICY_FILE) as f:
    POLICIES = json.load(f)

# Ensure live_alerts.json exists (DO NOT overwrite)
if not LIVE_ALERTS_FILE.exists():
    with open(LIVE_ALERTS_FILE, "w") as f:
        json.dump([], f)

last_alert_time = defaultdict(float)

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def uid_to_user(uid):
    return subprocess.getoutput(
        f"getent passwd {uid} | cut -d: -f1"
    )

def is_allowed(user, filepath):
    return filepath in POLICIES.get(user, {}).get("allowed", [])

def should_alert(key):
    now = time.time()
    if now - last_alert_time[key] > ALERT_COOLDOWN_SECONDS:
        last_alert_time[key] = now
        return True
    return False

def store_live_alert(alert):
    with open(LIVE_ALERTS_FILE, "r+") as f:
        data = json.load(f)
        data.append(alert)
        f.seek(0)
        json.dump(data, f, indent=2)

# ============================================================
# REAL-TIME AUDIT LOG MONITOR
# ============================================================

def monitor():
    print("[+] Monitoring /var/log/audit/audit.log")
    print("[+] Waiting for file access or permission changes...\n")

    with open(AUDIT_LOG, "r") as log:
        log.seek(0, 2)  # jump to end of file
        event = {}

        while True:
            line = log.readline()
            if not line:
                time.sleep(0.1)
                continue

            # ---------------- FILE ACCESS ----------------
            if "type=SYSCALL" in line and "resource_access" in line:
                event = {"kind": "RESOURCE"}
                for p in line.split():
                    if p.startswith("uid="):
                        event["uid"] = p.split("=")[1]

            elif "type=PATH" in line and event.get("kind") == "RESOURCE":
                filepath = None
                for p in line.split():
                    if p.startswith("name="):
                        filepath = p.replace("name=", "").strip('"')

                if not filepath:
                    event = {}
                    continue

                user = uid_to_user(event.get("uid"))
                if not user:
                    event = {}
                    continue

                if not is_allowed(user, filepath):
                    key = f"RESOURCE:{user}:{filepath}"
                    if should_alert(key):
                        alert = {
                            "timestamp": datetime.now().isoformat(),
                            "user_id": user,
                            "attack_type": "UNAUTHORIZED_RESOURCE_ACCESS",
                            "alert_level": "HIGH",
                            "resource": filepath,
                            "risk_score": 0.80,
                            "active_attack": True,
                            "source": "auditd"
                        }

                        store_live_alert(alert)

                        print("🚨 UNAUTHORIZED RESOURCE ACCESS")
                        print(alert)
                        print("-" * 60)

                event = {}

            # ---------------- PERMISSION CHANGE ----------------
            if "type=SYSCALL" in line and "permission_change" in line:
                event = {"kind": "PERMISSION"}
                for p in line.split():
                    if p.startswith("uid="):
                        event["uid"] = p.split("=")[1]
                    if p.startswith("comm="):
                        event["cmd"] = p.replace("comm=", "").strip('"')

            elif "type=PATH" in line and event.get("kind") == "PERMISSION":
                filepath = None
                for p in line.split():
                    if p.startswith("name="):
                        filepath = p.replace("name=", "").strip('"')

                if not filepath:
                    event = {}
                    continue

                user = uid_to_user(event.get("uid"))
                if not user:
                    event = {}
                    continue

                key = f"PERMISSION:{user}:{filepath}"
                if should_alert(key):
                    alert = {
                        "timestamp": datetime.now().isoformat(),
                        "user_id": user,
                        "attack_type": "UNAUTHORIZED_PERMISSION_CHANGE",
                        "alert_level": "CRITICAL",
                        "resource": filepath,
                        "risk_score": 0.95,
                        "active_attack": True,
                        "source": "auditd"
                    }

                    store_live_alert(alert)

                    print("🔥 UNAUTHORIZED PERMISSION CHANGE")
                    print(alert)
                    print("-" * 60)

                event = {}

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    monitor()
