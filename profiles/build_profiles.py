
import pandas as pd
import joblib
import os
import sys

class UserProfiler:
    def __init__(self, df):
        self.df = df

    def build_profiles(self):
        profiles = {}

        for user_id, group in self.df.groupby("user_id"):
            profiles[user_id] = {
                "avg_login_hour": group["hour_of_day"].mean(),
                "common_countries": group["country"].value_counts().head(3).index.tolist(),
                "common_resources": group["resource_name"].value_counts().head(3).index.tolist(),
                "avg_failed_attempts": group["failed_attempts_before_success"].mean(),
                "avg_resource_sensitivity": group["resource_sensitivity"].mean()
            }

        print(f"[PROFILES] Built profiles for {len(profiles)} users.")
        return profiles

    def save_profiles(self, profiles, path="profiles/user_profiles.pkl"):
        os.makedirs("profiles", exist_ok=True)
        joblib.dump(profiles, path)
        print(f"[PROFILES] Profiles saved to {path}")

if __name__ == "__main__":
    from pipeline.ingest import LogIngestor
    from pipeline.parser import LogParser
    from pipeline.features import FeatureEngineer

    ingestor = LogIngestor("data/raw_logs.csv")
    raw_df = ingestor.ingest()

    parser = LogParser(raw_df)
    clean_df = parser.clean()

    fe = FeatureEngineer(clean_df)
    featured_df = fe.add_behavioral_features()

    profiler = UserProfiler(featured_df)
    profiles = profiler.build_profiles()
    profiler.save_profiles(profiles)
