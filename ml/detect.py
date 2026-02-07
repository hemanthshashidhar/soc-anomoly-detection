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
        # =====================================================
        # LOAD MODEL BUNDLE (FIXED)
        # =====================================================
        bundle = joblib.load("ml/models/isolation_forest.pkl")

        self.model = bundle["model"]
        self.scaler = bundle["scaler"]
        self.features = bundle["features"]

    def detect(self):
        # =====================================================
        # INGEST + PARSE
        # =====================================================
        ingestor = LogIngestor("data/real_attack_logs.csv")
        raw_df = ingestor.ingest()

        parser = LogParser(raw_df)
        clean_df = parser.clean()

        # =====================================================
        # FEATURE ENGINEERING
        # =====================================================
        fe = FeatureEngineer(clean_df)
        df = fe.add_behavioral_features()

        # =====================================================
        # PREPARE ML INPUT
        # =====================================================
        df_ml = df.drop(
            columns=["is_anomaly", "user_id", "timestamp"],
            errors="ignore"
        )

        df_encoded = pd.get_dummies(df_ml)

        # Ensure feature alignment with training
        df_encoded = df_encoded.reindex(
            columns=self.features,
            fill_value=0
        )

        # =====================================================
        # SCALE + PREDICT
        # =====================================================
        X_scaled = self.scaler.transform(df_encoded)
        preds = self.model.predict(X_scaled)

        # IsolationForest: -1 = anomaly
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

        alert["country"] = row.get("country")
        alert["role"] = row.get("role")
        alert["resource"] = row.get("resource_name")

        alert["attack_type"] = narrative_engine.classify_attack(alert)
        alert["narrative"] = narrative_engine.build_narrative(alert)

        # Explicit real SSH marking
        alert["is_real_attack"] = (
            "Real SSH brute force attempt detected" in alert.get("reasons", [])
        )

        if alert["alert_level"]:
            alerts.append(alert)

    return df, alerts


if __name__ == "__main__":
    df, alerts = run_detection_with_alerts()
    print(f"\nGenerated {len(alerts)} alerts.\n")
    for alert in alerts[:5]:
        print(alert["narrative"])
