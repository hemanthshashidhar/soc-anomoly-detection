import pandas as pd

class FeatureEngineer:
    def __init__(self, df):
        self.df = df

    def add_behavioral_features(self):
        df = self.df.copy()

        # Time-based behavior
        df["is_night_login"] = df["hour_of_day"].apply(lambda x: 1 if x < 6 else 0)
        df["is_weekend"] = df["day_of_week"].apply(lambda x: 1 if x >= 5 else 0)

        # High failure attempts indicator
        df["high_failure_attempts"] = df["failed_attempts_before_success"].apply(
            lambda x: 1 if x >= 3 else 0
        )

        # Sensitive resource access flag
        df["is_sensitive_resource"] = df["resource_sensitivity"].apply(
            lambda x: 1 if x >= 4 else 0
        )

        # Privilege vs resource mismatch
        df["privilege_resource_mismatch"] = df.apply(
            lambda row: 1 if row["privilege_level"] < row["resource_sensitivity"] else 0,
            axis=1
        )

        print("[FEATURES] Behavioral features added.")
        return df

if __name__ == "__main__":
    from ingest import LogIngestor
    from parser import LogParser

    ingestor = LogIngestor("data/raw_logs.csv")
    raw_df = ingestor.ingest()

    parser = LogParser(raw_df)
    clean_df = parser.clean()

    fe = FeatureEngineer(clean_df)
    featured_df = fe.add_behavioral_features()

    print(featured_df.head())
