import subprocess
import csv
from datetime import datetime
from pathlib import Path

# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent
CSV_FILE = BASE_DIR / "data" / "real_attack_logs.csv"

print("[+] Real-time SSH log collector started")
print("[+] Listening to ssh.service")
print("[+] Writing to:", CSV_FILE)

# =========================================================
# ENSURE CSV EXISTS
# =========================================================

if not CSV_FILE.exists():
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp",
            "user_id",
            "ip",
            "attack_type",
            "success"
        ])

# =========================================================
# JOURNALCTL STREAM (CORRECT FOR PARROT)
# =========================================================

cmd = [
    "journalctl",
    "-u", "ssh",
    "-f",
    "--no-pager"
]

process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# =========================================================
# PARSE & WRITE
# =========================================================

for line in process.stdout:
    if not line:
        continue

    line = line.strip()
    print("[RAW]", line)

    # Example:
    # Failed password for invalid user fakeuser123 from ::1 port 47488

    if "Failed password for" in line:
        parts = line.split()

        try:
            # Handle "invalid user" case
            if "invalid user" in line:
                user = parts[parts.index("user") + 1]
            else:
                user = parts[parts.index("for") + 1]

            ip = parts[parts.index("from") + 1]
        except Exception:
            continue

        row = [
            datetime.now().isoformat(),
            user,
            ip,
            "SSH_BRUTE_FORCE",
            0
        ]

        with open(CSV_FILE, "a", newline="") as f:
            csv.writer(f).writerow(row)

        print("🚨 SSH FAILED LOGIN WRITTEN:", row)

    elif "Accepted password for" in line:
        parts = line.split()

        try:
            user = parts[parts.index("for") + 1]
            ip = parts[parts.index("from") + 1]
        except Exception:
            continue

        row = [
            datetime.now().isoformat(),
            user,
            ip,
            "SSH_SUCCESS",
            1
        ]

        with open(CSV_FILE, "a", newline="") as f:
            csv.writer(f).writerow(row)

        print("✅ SSH SUCCESS WRITTEN:", row)
	
