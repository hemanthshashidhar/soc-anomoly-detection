import time
from datetime import datetime
import subprocess

AUDIT_LOG = "/var/log/audit/audit.log"

print("[+] Permission Tamper Monitor started")

def uid_to_user(uid):
    return subprocess.getoutput(f"getent passwd {uid} | cut -d: -f1")

def monitor():
    with open(AUDIT_LOG, "r") as log:
        log.seek(0, 2)

        event = {}

        while True:
            line = log.readline()
            if not line:
                time.sleep(0.1)
                continue

            if "type=SYSCALL" in line and "permission_tamper" in line:
                event = {"raw": line}

                for part in line.split():
                    if part.startswith("uid="):
                        event["uid"] = part.split("=")[1]
                    if part.startswith("comm="):
                        event["command"] = part.split("=")[1].strip('"')

            if "type=PATH" in line and "name=" in line and event:
                for part in line.split():
                    if part.startswith("name="):
                        filepath = part.replace("name=", "").strip('"')
                        user = uid_to_user(event.get("uid"))

                        alert = {
                            "time": datetime.now().isoformat(),
                            "user": user,
                            "file": filepath,
                            "command": event.get("command"),
                            "severity": "CRITICAL"
                        }

                        print("🚨 PERMISSION TAMPERING DETECTED 🚨")
                        print(alert)
                        print("-" * 60)

                        event = {}

if __name__ == "__main__":
    monitor()
