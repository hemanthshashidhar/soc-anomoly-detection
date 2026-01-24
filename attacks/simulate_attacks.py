import pandas as pd
import random
from datetime import datetime

def simulate_identity_attacks(base_logs_path="data/raw_logs.csv", output_path="data/attack_logs.csv"):
    df = pd.read_csv(base_logs_path)

    attack_rows = []

    users = df["user_id"].unique()
    countries = ["Russia", "China", "Iran", "Brazil"]
    sensitive_resources = ["PayrollDB", "HR_Records", "DevOps_API"]

    for _ in range(50):
        user = random.choice(users)

        attack = {
            "user_id": user,
            "role": random.choice(["employee", "hr", "admin"]),
            "department": random.choice(["it", "finance", "hr"]),
            "privilege_level": random.randint(1, 3),
            "auth_type": "password",
            "login_result": "success",
            "failed_attempts_before_success": random.randint(3, 7),
            "timestamp": datetime.now().isoformat(),
            "hour_of_day": random.randint(0, 4),  # Night time
            "day_of_week": random.randint(0, 6),
            "country": random.choice(countries),
            "is_vpn": 1,
            "device_type": "unknown",
            "resource_name": random.choice(sensitive_resources),
            "resource_type": "database",
            "resource_sensitivity": random.randint(4, 5),
            "access_action": "read",
            "access_result": "success",
            "is_anomaly": 1
        }

        attack_rows.append(attack)

    attack_df = pd.DataFrame(attack_rows)

    combined = pd.concat([df, attack_df], ignore_index=True)
    combined.to_csv(output_path, index=False)

    print(f"[ATTACK SIM] Generated {len(attack_df)} attack events.")
    print(f"[ATTACK SIM] Saved combined logs to {output_path}")

if __name__ == "__main__":
    simulate_identity_attacks()
