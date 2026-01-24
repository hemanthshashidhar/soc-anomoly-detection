class AlertNotifier:
    def notify(self, alert):
        if alert["alert_level"]:
            print("\n🚨 SECURITY ALERT 🚨")
            print(f"User: {alert['user_id']}")
            print(f"Risk Score: {alert['risk_score']}")
            print(f"Alert Level: {alert['alert_level']}")
            print("Reasons:")
            for r in alert["reasons"]:
                print(f" - {r}")
