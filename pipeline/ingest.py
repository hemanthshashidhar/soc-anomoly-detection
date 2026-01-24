import pandas as pd
import os

REQUIRED_COLUMNS = [
    "user_id",
    "role",
    "department",
    "privilege_level",
    "auth_type",
    "login_result",
    "failed_attempts_before_success",
    "timestamp",
    "hour_of_day",
    "day_of_week",
    "country",
    "is_vpn",
    "device_type",
    "resource_name",
    "resource_type",
    "resource_sensitivity",
    "access_action",
    "access_result",
    "is_anomaly"
]

class LogIngestor:
    def __init__(self, log_path):
        self.log_path = log_path

    def load_logs(self):
        if not os.path.exists(self.log_path):
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

        df = pd.read_csv(self.log_path)
        return df

    def validate_schema(self, df):
        missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing:
            raise ValueError(f"Missing required columns: {missing}")
        return True

    def ingest(self):
        df = self.load_logs()
        self.validate_schema(df)
        print(f"[INGEST] Successfully ingested {len(df)} log events.")
        return df

if __name__ == "__main__":
    ingestor = LogIngestor("data/raw_logs.csv")
    df = ingestor.ingest()
    print(df.head())
