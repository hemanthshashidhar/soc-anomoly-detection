import pandas as pd
import subprocess
import re
from datetime import datetime

def parse_hydra_attacks(output_path="data/hydra_attack_logs.csv"):
    rows = []

    result = subprocess.run(
        ["journalctl", "--no-pager"],
        stdout=subprocess.PIPE,
        text=True
    )

    for line in result.stdout.split("\n"):
        if "hydra_test" in line and ("authentication failure" in line or "Failed password" in line):
            ip_match = re.search(r"from ([\d\.]+)", line)
            ip = ip_match.group(1) if ip_match else "127.0.0.1"

            row = {
                "user_id": "hydra_test",
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
        print(f"[HYDRA PARSER] Saved {len(rows)} hydra attack events to {output_path}")
    else:
        print("[HYDRA PARSER] No Hydra attacks found.")

if __name__ == "__main__":
    parse_hydra_attacks()
