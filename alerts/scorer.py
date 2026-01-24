import sys
import os

import joblib

class RiskScorer:
    def __init__(self, profiles_path="profiles/user_profiles.pkl"):
        self.user_profiles = joblib.load(profiles_path)

    def score_event(self, row):
        risk = 0
        user_id = row["user_id"]
        profile = self.user_profiles.get(user_id, {})

        # ML anomaly contributes heavily
        if row.get("ml_anomaly", 0) == 1:
            risk += 40

        # New country for user
        if profile and row["country"] not in profile["common_countries"]:
            risk += 15

        # Unusual login hour
        if profile and abs(row["hour_of_day"] - profile["avg_login_hour"]) > 6:
            risk += 10

        # Sensitive resource access
        if row["resource_sensitivity"] >= 4:
            risk += 15

        # VPN usage
        if row["is_vpn"] == 1:
            risk += 10

        # High failure attempts
        if row["failed_attempts_before_success"] >= 3:
            risk += 10

        return min(risk, 100)
