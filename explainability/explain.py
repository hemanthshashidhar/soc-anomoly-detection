import sys
import os

import joblib

class Explainer:
    def __init__(self, profiles_path="profiles/user_profiles.pkl"):
        self.user_profiles = joblib.load(profiles_path)

    def explain(self, row):
        reasons = []
        user_id = row["user_id"]
        profile = self.user_profiles.get(user_id, {})

        if row.get("ml_anomaly", 0) == 1:
            reasons.append("ML model detected anomalous behavior")

        if profile and row["country"] not in profile["common_countries"]:
            reasons.append(f"New country for user: {row['country']}")

        if profile and abs(row["hour_of_day"] - profile["avg_login_hour"]) > 6:
            reasons.append("Login time deviates from user's normal pattern")

        if row["resource_sensitivity"] >= 4:
            reasons.append("Access to highly sensitive resource")

        if row["is_vpn"] == 1:
            reasons.append("Login via VPN")

        if row["failed_attempts_before_success"] >= 3:
            reasons.append("Multiple failed login attempts before success")

        return reasons
