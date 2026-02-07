# 🛡️ AI-Based Identity Threat Detection System

An AI-powered SOC (Security Operations Center) system with real-time cyber attack monitoring, behavioral anomaly detection, and explainable AI narratives.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![ML](https://img.shields.io/badge/ML-Isolation%20Forest-green.svg)
![Accuracy](https://img.shields.io/badge/Accuracy-99.52%25-brightgreen.svg)

---

## 🎯 Features

- ✅ **Real-Time SSH Attack Detection** - Live monitoring of SSH brute force attempts
- ✅ **Resource Access Monitoring** - Unauthorized file access detection
- ✅ **ML-Based Anomaly Detection** - Isolation Forest with 99.52% accuracy
- ✅ **Hybrid Detection** - ML + rule-based security policies
- ✅ **Explainable AI** - Human-readable attack narratives
- ✅ **Live SOC Dashboard** - Real-time visualization with Streamlit
- ✅ **Risk Scoring** - Dynamic risk assessment (0-100 scale)

---

## 🏗️ Project Structure

```
soc-detection/
│
├── alerts/                         # Alert Generation & Scoring
│   ├── alert_engine.py             # Risk scoring and alert levels
│   ├── scorer.py                   # Alert severity calculator
│   └── notifier.py                 # Alert notifications
│
├── dashboard/                      # SOC Dashboard
│   └── app.py                      # Streamlit dashboard
│
├── intelligence/                   # AI Intelligence Layer
│   ├── identity_tracker.py         # User risk tracking
│   └── narrative_engine.py         # Attack narratives
│
├── ml/                             # Machine Learning
│   ├── models/
│   │   ├── isolation_forest.pkl    # Trained model
│   │   ├── scaler.pkl              # Feature scaler
│   │   └── isolation_forest_metrics.json
│   ├── train_isolation_forest.py   # Model training
│   ├── detect.py                   # Batch detection
│   └── synthetic_data_generator.py # Data generator
│
├── pipeline/                       # Data Pipeline
│   ├── features.py                 # Feature engineering
│   ├── realtime_resource_monitor.py # File monitor
│   └── realtime_ssh_monitor.py     # SSH monitor
│
├── profiles/                       # User Profiling
│   ├── build_profiles.py           # Profile builder
│   └── resource_policies.json      # Access policies
│
├── data/                           # Data Storage
│   └── live_alerts.json            # Real-time alerts
│
├── realtime_monitor.py             # Main SSH monitor
├── start_project.sh                # Quick start script
├── setup_audit_rules.sh            # Auditd setup
└── requirements.txt                # Dependencies
```

---

## 🚀 Quick Start

### Prerequisites
- **OS**: Linux (Ubuntu/Debian/Parrot OS)
- **Python**: 3.8+
- **Permissions**: Root access (sudo)

### Installation

```bash
# 1. Clone repository
git clone https://github.com/hemanthshashidhar/soc-detection.git
cd soc-detection

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize data directory
mkdir -p data
echo "[]" > data/live_alerts.json
```

---

## 🎮 Running the System

### Method 1: Quick Start
```bash
chmod +x start_project.sh
./start_project.sh
```

### Method 2: Manual Start (3 Terminals)

**Terminal 1 - Dashboard:**
```bash
streamlit run dashboard/app.py
```
Dashboard opens at: http://localhost:8501

**Terminal 2 - SSH Monitor:**
```bash
sudo python3 realtime_monitor.py
```

**Terminal 3 - Resource Monitor (Optional):**
```bash
sudo bash setup_audit_rules.sh
sudo python3 pipeline/realtime_resource_monitor.py
```

---

## 📊 ML Model Performance

| Metric | Score |
|--------|-------|
| **Accuracy** | 99.52% |
| **Precision** | 98.25% |
| **Recall** | 99.84% |
| **F1-Score** | 99.04% |
| **ROC-AUC** | 99.83% |

**Features Used:**
- `failed_attempts` - Failed login count
- `success_logins` - Successful logins
- `unique_ips` - Distinct IP addresses
- `access_count` - Resource access frequency
- `sensitive_access` - High-sensitivity access
- `hour` - Time-based patterns

---

## 🧪 Testing

### Test SSH Attack Detection
```bash
# Generate failed SSH attempts
ssh invaliduser@localhost
# Enter wrong password multiple times
```

### Test Resource Monitor
```bash
# Access protected file
cat /secure_data/confidential.txt
```

### View Live Alerts
```bash
cat data/live_alerts.json | jq
```

---

## 🔧 Configuration

### Alert Thresholds (`alerts/alert_engine.py`)
```python
CRITICAL: risk_score >= 70
HIGH:     risk_score >= 40
MEDIUM:   risk_score >= 20
LOW:      risk_score >= 10
```

### Resource Policies (`profiles/resource_policies.json`)
```json
{
  "admin": {
    "allowed": ["/secure_data/admin_files"]
  }
}
```

---

## 🛠️ Troubleshooting

### Dashboard Shows No Data
```bash
# Check alerts file
cat data/live_alerts.json

# Add test alert
python3 -c "
import json
from datetime import datetime
alerts = [{
    'timestamp': datetime.now().isoformat(),
    'user_id': 'test',
    'attack_type': 'SSH_BRUTE_FORCE',
    'alert_level': 'HIGH',
    'risk_score': 85,
    'source': 'ssh',
    'reasons': ['Test alert'],
    'narrative': 'Test alert'
}]
with open('data/live_alerts.json', 'w') as f:
    json.dump(alerts, f)
"
```

### SSH Monitor Not Working
```bash
# Check journalctl access
sudo journalctl -f --no-pager | grep "Failed password"

# Verify monitor is running
ps aux | grep realtime_monitor
```

### Resource Monitor Issues
```bash
# Check auditd status
sudo systemctl status auditd

# Verify audit rules
sudo auditctl -l
```

---

## 📦 Dependencies

- `streamlit` - Dashboard
- `pandas` - Data processing
- `scikit-learn` - ML models
- `matplotlib` - Visualizations
- `joblib` - Model persistence

See `requirements.txt` for full list.

---

## 👨💻 Author

**Hemanth Shashidhar**
- GitHub: [@hemanthshashidhar](https://github.com/hemanthshashidhar)
- Repository: [soc-detection](https://github.com/hemanthshashidhar/soc-detection)

---

## 📄 License

MIT License

---

**⭐ Star this repo if you find it useful!**
