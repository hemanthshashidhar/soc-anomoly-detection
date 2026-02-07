import numpy as np
import pandas as pd
from pathlib import Path
import random

# ======================================================
# CONFIG
# ======================================================

OUTPUT_FILE = Path(__file__).resolve().parent.parent / "data" / "synthetic_security_logs.csv"
NUM_SAMPLES = 10000
ATTACK_RATIO = 0.25   # 25% attack data

random.seed(42)
np.random.seed(42)

print("[+] Generating synthetic security data...")
print("[+] Samples:", NUM_SAMPLES)

# ======================================================
# DATA GENERATION
# ======================================================

data = []

for _ in range(NUM_SAMPLES):
    is_attack = np.random.rand() < ATTACK_RATIO

    hour = np.random.randint(0, 24)

    if not is_attack:
        # ---------------- NORMAL BEHAVIOR ----------------
        failed_attempts = np.random.poisson(0.2)
        success_logins = np.random.poisson(1.5)
        unique_ips = np.random.randint(1, 3)
        access_count = np.random.randint(1, 5)
        sensitive_access = 0

        label = 0

    else:
        # ---------------- ATTACK BEHAVIOR ----------------
        failed_attempts = np.random.randint(5, 30)
        success_logins = np.random.randint(0, 2)
        unique_ips = np.random.randint(3, 15)
        access_count = np.random.randint(10, 50)
        sensitive_access = np.random.choice([0, 1], p=[0.3, 0.7])

        label = 1

    data.append([
        failed_attempts,
        success_logins,
        unique_ips,
        access_count,
        sensitive_access,
        hour,
        label
    ])

# ======================================================
# SAVE DATASET
# ======================================================

df = pd.DataFrame(
    data,
    columns=[
        "failed_attempts",
        "success_logins",
        "unique_ips",
        "access_count",
        "sensitive_access",
        "hour",
        "label"
    ]
)

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(OUTPUT_FILE, index=False)

print("[+] Synthetic dataset created")
print("[+] File saved to:", OUTPUT_FILE)
print(df.head())
