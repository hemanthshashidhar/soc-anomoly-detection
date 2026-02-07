import json
import time
from pathlib import Path
from datetime import datetime
import numpy as np
import joblib

# ======================================================
# PATHS
# ======================================================

BASE_DIR = Path(__file__).resolve().parent.parent

LIVE_ALERTS_FILE = BASE_DIR / "data" / "live_alerts.json"
MODEL_FILE = BASE_DIR / "ml" / "models" / "isolation_forest.pkl"

print("[+] Starting real-time ML inference engine")

# ======================================================
# LOAD MODEL
# ======================================================

bundle = joblib.load(MODEL_FILE)
model = bundle["model"]
scaler = bundle["scaler"]
FEATURES = bundle["features"]

print("[+] Model loaded successfully")

# ======================================================
# HELPER FUNCTIONS
# ======================================================

def extract_features(events):
    """
    Convert live events into ML feature vector
    """
    failed_attempts = sum(
        1 for e in events if e.get("attack_type") == "SSH_FAILED_LOGIN"
    )

    success_logins = sum(
        1 for e in events if e.get("attack_type") == "SSH_SUCCESS_LOGIN"
    )

    unique_ips = len(set(
        e.get("ip") for e in events if "ip" in e
    ))

    access_count = sum(
        1 for e in events if e.get("source") == "auditd"
    )

    sensitive_access = int(any(
        e.get("sensitive", False) for e in events
    ))

    hour = datetime.now().hour

    return [
        failed_attempts,
        success_logins,
        unique_ips,
        access_count,
        sensitive_access,
        hour
    ]

def compute_risk_score(X_scaled):
    score = -model.score_samples(X_scaled)[0]
    return float(max(0.0, min(1.0, score)))

# ======================================================
# MAIN LOOP
# ======================================================

while True:
    try:
        if not LIVE_ALERTS_FILE.exists():
            time.sleep(5)
            continue

        with open(LIVE_ALERTS_FILE, "r") as f:
            alerts = json.load(f)

        if not alerts:
            time.sleep(5)
            continue

        # Use last 1 minute of events
        now = datetime.now()
        window_events = [
            e for e in alerts
            if "timestamp" in e and
            (now - datetime.fromisoformat(e["timestamp"])).seconds <= 60
        ]

        if not window_events:
            time.sleep(5)
            continue

        # Feature extraction
        feature_vector = extract_features(window_events)
        X = np.array(feature_vector).reshape(1, -1)
        X_scaled = scaler.transform(X)

        # ML prediction
        pred = model.predict(X_scaled)[0]
        is_attack = 1 if pred == -1 else 0
        risk_score = compute_risk_score(X_scaled)

        # Attach ML output to latest event
        alerts[-1]["ml_prediction"] = "attack" if is_attack else "normal"
        alerts[-1]["ml_risk_score"] = round(risk_score, 3)
        alerts[-1]["ml_model"] = "IsolationForest"

        with open(LIVE_ALERTS_FILE, "w") as f:
            json.dump(alerts, f, indent=2)

        print("[ML] Prediction:", alerts[-1]["ml_prediction"],
              "Risk:", alerts[-1]["ml_risk_score"])

        time.sleep(5)

    except Exception as e:
        print("[ERROR]", e)
        time.sleep(5)
