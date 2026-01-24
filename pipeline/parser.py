import pandas as pd

class LogParser:
    def __init__(self, df):
        self.df = df

    def clean(self):
        df = self.df.copy()

        # Drop rows with critical missing values
        df.dropna(subset=["user_id", "timestamp", "resource_name"], inplace=True)

        # Normalize categorical fields
        df["role"] = df["role"].str.lower()
        df["department"] = df["department"].str.lower()
        df["country"] = df["country"].str.title()
        df["device_type"] = df["device_type"].str.lower()
        df["resource_type"] = df["resource_type"].str.lower()
        df["access_action"] = df["access_action"].str.lower()

        # Convert numeric fields safely
        df["failed_attempts_before_success"] = pd.to_numeric(
            df["failed_attempts_before_success"], errors="coerce"
        ).fillna(0)

        df["privilege_level"] = pd.to_numeric(
            df["privilege_level"], errors="coerce"
        ).fillna(1)

        df["resource_sensitivity"] = pd.to_numeric(
            df["resource_sensitivity"], errors="coerce"
        ).fillna(1)

        # Enforce binary fields
        df["is_vpn"] = df["is_vpn"].apply(lambda x: 1 if x == 1 else 0)
        df["is_anomaly"] = df["is_anomaly"].apply(lambda x: 1 if x == 1 else 0)

        print(f"[PARSER] Cleaned dataset: {len(df)} rows")
        return df

if __name__ == "__main__":
    from ingest import LogIngestor

    ingestor = LogIngestor("data/raw_logs.csv")
    raw_df = ingestor.ingest()

    parser = LogParser(raw_df)
    clean_df = parser.clean()

    print(clean_df.head())
