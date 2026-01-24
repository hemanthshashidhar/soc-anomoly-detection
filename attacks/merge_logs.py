import pandas as pd

base = pd.read_csv("data/raw_logs.csv")

frames = [base]

try:
    ssh = pd.read_csv("data/ssh_attack_logs.csv")
    frames.append(ssh)
except:
    print("[MERGE] No SSH attack logs found")

try:
    hydra = pd.read_csv("data/hydra_attack_logs.csv")
    frames.append(hydra)
except:
    print("[MERGE] No Hydra attack logs found")

combined = pd.concat(frames, ignore_index=True)
combined.to_csv("data/real_attack_logs.csv", index=False)

print("[MERGE] Created data/real_attack_logs.csv")
