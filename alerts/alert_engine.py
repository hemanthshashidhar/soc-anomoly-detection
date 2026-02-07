class AlertEngine:
    def __init__(self):
        pass

    def process_event(self, row):
        reasons = []
        risk_score = 0
        alert_level = None

        # Rule-based detection for SSH brute force (REAL ATTACK)
        if row["auth_type"] == "ssh" and row["access_result"] == "failed":
            reasons.append("Real SSH brute force attempt detected")
            risk_score += 80

        # ML-based anomaly
        if row.get("ml_anomaly", 0) == 1:
            reasons.append("ML model detected anomalous behavior")
            risk_score += 40

        # Time anomaly
        if row["hour_of_day"] < 5:
            reasons.append("Login time deviates from user's normal pattern")
            risk_score += 10

        # Sensitive resource access
        if row["resource_sensitivity"] >= 4:
            reasons.append("Access to highly sensitive resource")
            risk_score += 15

        # VPN usage
        if row["is_vpn"] == 1:
            reasons.append("Login via VPN")
            risk_score += 10

        # Failed attempts
        if row["failed_attempts_before_success"] >= 3:
            reasons.append("Multiple failed login attempts before success")
            risk_score += 10

        # Determine alert level based on risk score
        if risk_score >= 70:
            alert_level = "CRITICAL"
        elif risk_score >= 40:
            alert_level = "HIGH"
        elif risk_score >= 20:
            alert_level = "MEDIUM"
        elif risk_score >= 10:
            alert_level = "LOW"
        else:
            alert_level = None

        return {
            "user_id": row["user_id"],
            "risk_score": risk_score,
            "alert_level": alert_level,
            "reasons": reasons
        }
