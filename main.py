import sys
import os

# Add project root to PYTHONPATH
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from dashboard.app import run_dashboard

if __name__ == "__main__":
    run_dashboard()
