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
├── attacks/ # Attack parsing and real attack integration
├── alerts/ # Alert generation logic
├── dashboard/ # Streamlit SOC dashboard
├── intelligence/ # Attack classification and narrative engine
├── ml/ # Anomaly detection models
├── pipeline/ # Data ingestion and feature engineering
├── profiles/ # User behavioral profiling
├── data/ # Logs (ignored in Git)
├── realtime_monitor.py # Real-time AI attack monitor
├── requirements.txt
└── README.md


## How to Run

## ⚙️ Installation

### Clone the Repository

git clone https://github.com/YOUR_USERNAME/identity-threat-ai.git

cd identity-threat-ai

## Create Virtual Environment

### Install Dependencies

pip install -r requirements.txt

## Run Dashboard
streamlit run dashboard/app.py

## Run Real-Time Monitor
sudo python3 realtime_monitor.py


