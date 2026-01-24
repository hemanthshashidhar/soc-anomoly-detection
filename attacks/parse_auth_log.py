import pandas as pd
import subprocess
import re
from datetime import datetime

def parse_ssh_from_journal(output_path="data/ssh_attack_logs.csv"):
    rows = []

    # Get full journal logs
    result = subprocess.run(
        ["journalctl", "--no-pager"],
        stdout=subprocess.PIPE,
        text=True
    )

    for line in result.stdout.split("\n"):
        if "Failed password" in line:
            match = re.search(r"Failed password for .* user (\w+) from ([\:\.\d]+)", line)
            if match:
                user = match.group(1)
                ip = match.group(2)

                row = {
                    "user_id": user,
                    "role": "employee",
                    "department": "it",
                    "privilege_level": 1,
                    "auth_type": "ssh",
                    "login_result": "failed",
                    "failed_attempts_before_success": 1,
                    "timestamp": datetime.now().isoformat(),
                    "hour_of_day": datetime.now().hour,
                    "day_of_week": datetime.now().weekday(),
                    "country": "Unknown",
                    "is_vpn": 0,
                    "device_type": "unknown",
                    "resource_name": "SSH",
                    "resource_type": "server",
                    "resource_sensitivity": 4,
                    "access_action": "login",
                    "access_result": "failed",
                    "is_anomaly": 1
                }

                rows.append(row)

    if rows:
        df = pd.DataFrame(rows)
        df.to_csv(output_path, index=False)
        print(f"[SSH PARSER] Saved {len(rows)} attack events to {output_path}")
    else:
        print("[SSH PARSER] No SSH attacks found in journal.")

if __name__ == "__main__":
    parse_ssh_from_journal()
