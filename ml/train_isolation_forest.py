import pandas as pd
import numpy as np
from pathlib import Path
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)
from sklearn.preprocessing import MinMaxScaler

# ======================================================
# PATHS
# ======================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = BASE_DIR / "data" / "synthetic_security_logs.csv"
MODEL_FILE = BASE_DIR / "ml" / "models" / "isolation_forest.pkl"
METRICS_FILE = BASE_DIR / "ml" / "models" / "isolation_forest_metrics.json"

MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)

print("[+] Loading synthetic dataset from:", DATA_FILE)

# ======================================================
# LOAD DATA
# ======================================================

df = pd.read_csv(DATA_FILE)

FEATURES = [
    "failed_attempts",
    "success_logins",
    "unique_ips",
    "access_count",
    "sensitive_access",
    "hour"
]

X = df[FEATURES]
y = df["label"]  # 0 = normal, 1 = attack

# ======================================================
# SCALE FEATURES (IMPORTANT)
# ======================================================

scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# ======================================================
# TRAIN / TEST SPLIT
# ======================================================

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# ======================================================
# TRAIN ISOLATION FOREST
# ======================================================

print("[+] Training Isolation Forest model...")

model = IsolationForest(
    n_estimators=200,
    contamination=0.25,   # matches synthetic attack ratio
    random_state=42
)

model.fit(X_train)

# ======================================================
# PREDICTION
# IsolationForest output:
#   -1 = anomaly
#    1 = normal
# ======================================================

y_pred_raw = model.predict(X_test)
y_pred = np.where(y_pred_raw == -1, 1, 0)

# ======================================================
# ANOMALY SCORE → RISK SCORE (0–1)
# ======================================================

scores = -model.score_samples(X_test)
risk_scores = (scores - scores.min()) / (scores.max() - scores.min())

# ======================================================
# EVALUATION METRICS
# ======================================================

metrics = {
    "accuracy": round(accuracy_score(y_test, y_pred), 4),
    "precision": round(precision_score(y_test, y_pred), 4),
    "recall": round(recall_score(y_test, y_pred), 4),
    "f1_score": round(f1_score(y_test, y_pred), 4),
    "roc_auc": round(roc_auc_score(y_test, risk_scores), 4),
    "train_samples": int(len(X_train)),
    "test_samples": int(len(X_test))
}

print("[+] Evaluation Metrics")
for k, v in metrics.items():
    print(f"    {k}: {v}")

# ======================================================
# SAVE MODEL + SCALER + METRICS
# ======================================================

joblib.dump(
    {
        "model": model,
        "scaler": scaler,
        "features": FEATURES
    },
    MODEL_FILE
)

import json
with open(METRICS_FILE, "w") as f:
    json.dump(metrics, f, indent=2)

print("[+] Model saved to:", MODEL_FILE)
print("[+] Metrics saved to:", METRICS_FILE)
