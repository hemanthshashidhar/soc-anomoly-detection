import sys
import os

import pandas as pd
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from pipeline.ingest import LogIngestor
from pipeline.parser import LogParser
from pipeline.features import FeatureEngineer

class AnomalyModelTrainer:
    def __init__(self):
        pass

    def prepare_data(self):
        ingestor = LogIngestor("data/raw_logs.csv")
        raw_df = ingestor.ingest()

        parser = LogParser(raw_df)
        clean_df = parser.clean()

        fe = FeatureEngineer(clean_df)
        df = fe.add_behavioral_features()

        labels = df["is_anomaly"]

        df_ml = df.drop(columns=["is_anomaly", "user_id", "timestamp"], errors="ignore")
        df_encoded = pd.get_dummies(df_ml)

        return df_encoded, labels

    def train(self):
        X, labels = self.prepare_data()

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Train only on normal behavior
        X_train = X_scaled[labels == 0]

        model = IsolationForest(
            n_estimators=200,
            contamination=0.15,
            random_state=42
        )
        model.fit(X_train)

        os.makedirs("ml/models", exist_ok=True)
        joblib.dump(model, "ml/models/isolation_forest.pkl")
        joblib.dump(scaler, "ml/models/scaler.pkl")
        joblib.dump(X.columns.tolist(), "ml/models/feature_columns.pkl")

        print("[ML] Model, scaler, and features saved.")

if __name__ == "__main__":
    trainer = AnomalyModelTrainer()
    trainer.train()
