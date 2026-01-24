class AttackNarrativeEngine:
    def __init__(self):
        pass

    def classify_attack(self, alert):
        reasons = alert.get("reasons", [])
        role = alert.get("role", "")
        resource = alert.get("resource", "")

        if any("failed login" in r.lower() for r in reasons):
            return "Credential Brute Force / Credential Stuffing"

        if "highly sensitive" in " ".join(reasons).lower() and role != "admin":
            return "Privilege Abuse or Insider Threat"

        if alert.get("active_attack"):
            return "Account Under Active Takeover"

        if "vpn" in " ".join(reasons).lower():
            return "Suspicious Remote Access"

        return "Anomalous Access Pattern"

    def build_narrative(self, alert):
        attack_type = self.classify_attack(alert)

        narrative = f"""
ATTACK NARRATIVE:
User {alert['user_id']} is likely involved in a {attack_type}.

Observed Behavior:
- Alert Level: {alert['alert_level']}
- Risk Score: {alert['risk_score']}
- Resource Targeted: {alert.get('resource')}
- Country: {alert.get('country')}
- Risk Trend: {alert.get('risk_trend')}

Key Indicators:
"""
        for r in alert["reasons"]:
            narrative += f"- {r}\n"

        if alert.get("active_attack"):
            narrative += "\n⚠️ This account appears to be under active compromise progression."

        return narrative.strip()
