# AI-Based Identity Threat Detection System

An AI-powered identity threat detection system with real-time cyber attack monitoring and SOC-style dashboard.

## Features
- Behavioral anomaly detection using Machine Learning
- Hybrid detection (ML + security rules)
- Real-time SSH attack monitoring
- Live SOC dashboard (Streamlit)
- Explainable AI alerts and narratives
- Tested using real attacks on Parrot OS

## Tech Stack
- Python
- Scikit-learn
- Pandas, NumPy
- Streamlit
- Parrot OS

## Project Structure
identity_threat_ai_poc/
├── attacks/
├── alerts/
├── dashboard/
├── intelligence/
├── ml/
├── pipeline/
├── profiles/
├── data/
└── realtime_monitor.py


## How to Run

### Install Dependencies
```bash
pip install -r requirements.txt

Run Dashboard
streamlit run dashboard/app.py

Run Real-Time Monitor
sudo python3 realtime_monitor.py

Author

Hemant Kumar


Save.

---

# Step 4 — Create requirements.txt

```bash
nano requirements.txt


Paste:

pandas
numpy
scikit-learn
streamlit
streamlit-autorefresh
matplotlib


Save.
