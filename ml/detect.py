import pandas as pd
import joblib

from pipeline.ingest import LogIngestor
from pipeline.parser import LogParser
from pipeline.features import FeatureEngineer
from alerts.alert_engine import AlertEngine
from intelligence.identity_tracker import IdentityRiskTracker
from intelligence.narrative_engine import AttackNarrativeEngine


class AnomalyDetector:
    def __init__(self):
        self.model = joblib.load("ml/models/isolation_forest.pkl")
        self.scaler = joblib.load("ml/models/scaler.pkl")
        self.features = joblib.load("ml/models/feature_columns.pkl")

    def detect(self):
        ingestor = LogIngestor("data/real_attack_logs.csv")
        raw_df = ingestor.ingest()

        parser = LogParser(raw_df)
        clean_df = parser.clean()

        fe = FeatureEngineer(clean_df)
        df = fe.add_behavioral_features()

        df_ml = df.drop(columns=["is_anomaly", "user_id", "timestamp"], errors="ignore")
        df_encoded = pd.get_dummies(df_ml)
        df_encoded = df_encoded.reindex(columns=self.features, fill_value=0)

        X_scaled = self.scaler.transform(df_encoded)
        preds = self.model.predict(X_scaled)

        df["ml_anomaly"] = [1 if p == -1 else 0 for p in preds]
        return df


def run_detection_with_alerts():
    detector = AnomalyDetector()
    df = detector.detect()

    alert_engine = AlertEngine()
    tracker = IdentityRiskTracker()
    narrative_engine = AttackNarrativeEngine()

    alerts = []

    for _, row in df.iterrows():
        alert = alert_engine.process_event(row)

        tracker.update(row["user_id"], alert["risk_score"])
        trend, history = tracker.get_risk_trend(row["user_id"])
        active_attack = tracker.is_under_active_attack(row["user_id"])

        alert["risk_trend"] = trend
        alert["risk_history"] = history
        alert["active_attack"] = active_attack

        alert["country"] = row["country"]
        alert["role"] = row["role"]
        alert["resource"] = row["resource_name"]

        alert["attack_type"] = narrative_engine.classify_attack(alert)
        alert["narrative"] = narrative_engine.build_narrative(alert)
        # Mark real SSH attacks explicitly
        alert["is_real_attack"] = "Real SSH brute force attempt detected" in alert["reasons"]

        if alert["alert_level"]:
            alerts.append(alert)

    return df, alerts


if __name__ == "__main__":
    df, alerts = run_detection_with_alerts()
    print(f"\nGenerated {len(alerts)} alerts.\n")
    for alert in alerts[:5]:
        print(alert["narrative"])
