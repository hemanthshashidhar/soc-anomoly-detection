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
    try:
        with open(LIVE_ALERTS_FILE, "r") as f:
            data = json.load(f)
    except:
        data = []
    
    data.append(alert)
    
    with open(LIVE_ALERTS_FILE, "w") as f:
        json.dump(data[-100:], f, indent=2)

# ============================================================
# REAL-TIME AUDIT LOG MONITOR
# ============================================================

def monitor():
    print("[+] Monitoring /var/log/audit/audit.log")
    print("[+] Waiting for file access or permission changes...\n")

    try:
        with open(AUDIT_LOG, "r") as log:
            log.seek(0, 2)  # jump to end of file

            while True:
                line = log.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                # Look for SYSCALL entries with our audit keys
                if "type=SYSCALL" in line and ("key=\"resource_access\"" in line or "key=\"permission_change\"" in line):
                    # Extract UID
                    uid = None
                    for part in line.split():
                        if part.startswith("uid="):
                            uid = part.split("=")[1]
                            break
                    
                    if not uid:
                        continue
                    
                    # Read next line to get PATH with filename
                    path_line = log.readline()
                    if "type=PATH" not in path_line:
                        continue
                    
                    # Extract filepath from PATH line
                    filepath = None
                    for part in path_line.split():
                        if part.startswith("name="):
                            filepath = part.split("=")[1].strip('"')
                            break
                    
                    if not filepath or "/secure_data" not in filepath:
                        continue
                    
                    user = uid_to_user(uid) or f"uid_{uid}"
                    
                    # Determine if it's access or permission change
                    is_permission_change = "key=\"permission_change\"" in line
                    
                    # Check if access is allowed
                    if not is_allowed(user, filepath):
                        key = f"{'PERMISSION' if is_permission_change else 'RESOURCE'}:{user}:{filepath}"
                        if should_alert(key):
                            if is_permission_change:
                                alert = {
                                    "timestamp": datetime.now().isoformat(),
                                    "user_id": user,
                                    "attack_type": "UNAUTHORIZED_PERMISSION_CHANGE",
                                    "alert_level": "CRITICAL",
                                    "resource": filepath,
                                    "risk_score": 0.95,
                                    "active_attack": True,
                                    "source": "auditd",
                                    "reasons": [f"Unauthorized permission change on {filepath}", "Critical security policy violation"],
                                    "narrative": f"CRITICAL SECURITY ALERT: User '{user}' made unauthorized permission changes to '{filepath}'. This is a severe security violation that could indicate privilege escalation or system compromise."
                                }
                                print("🔥 UNAUTHORIZED PERMISSION CHANGE")
                            else:
                                alert = {
                                    "timestamp": datetime.now().isoformat(),
                                    "user_id": user,
                                    "attack_type": "UNAUTHORIZED_RESOURCE_ACCESS",
                                    "alert_level": "HIGH",
                                    "resource": filepath,
                                    "risk_score": 0.80,
                                    "active_attack": True,
                                    "source": "auditd",
                                    "reasons": [f"Unauthorized access to {filepath}", "Resource access policy violation"],
                                    "narrative": f"Security violation: User '{user}' attempted unauthorized access to protected resource '{filepath}'. This violates the established resource access policies and may indicate malicious activity."
                                }
                                print("🚨 UNAUTHORIZED RESOURCE ACCESS")
                            
                            store_live_alert(alert)
                            print(f"User: {user}")
                            print(f"File: {filepath}")
                            print("-" * 60)
                                
    except FileNotFoundError:
        print("❌ Audit log not found. Make sure auditd is running and you have permissions.")
    except PermissionError:
        print("❌ Permission denied. Run with sudo to access audit logs.")

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    monitor()
