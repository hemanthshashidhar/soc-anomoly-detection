import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import sys
import os
import json
from pathlib import Path

import streamlit as st
import pandas as pd
from streamlit_autorefresh import st_autorefresh
from ml.detect import run_detection_with_alerts

# =========================================================
# PATH SETUP
# =========================================================
BASE_DIR = Path(__file__).resolve().parent.parent
LIVE_ALERTS_FILE = BASE_DIR / "data" / "live_alerts.json"

sys.path.append(str(BASE_DIR))

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(page_title="Identity Threat SOC", layout="wide")
st_autorefresh(interval=50000, key="live_refresh")

# =========================================================
# HEADER
# =========================================================
st.markdown("""
<h1 style='color:#00FFAA; text-align:center;'>🛡️ Identity Threat Intelligence SOC</h1>
<h4 style='text-align:center; color:#888;'>AI-Powered Identity Threat Detection & Real-Time Monitoring</h4>
""", unsafe_allow_html=True)

# =========================================================
# SEVERITY COLORING
# =========================================================
def severity_color(level):
    if level == "CRITICAL":
        return "background-color: #ff4d4d; color: white;"
    elif level == "HIGH":
        return "background-color: #ff944d; color: black;"
    elif level == "MEDIUM":
        return "background-color: #ffe066; color: black;"
    return ""

# =========================================================
# LOAD BATCH (ML) ALERTS — DO NOT TOUCH
# =========================================================
df, alerts = run_detection_with_alerts()
alerts_df = pd.DataFrame(alerts)

# =========================================================
# LOAD LIVE ALERTS (SSH + AUDITD)
# =========================================================
try:
    with open(LIVE_ALERTS_FILE, "r") as f:
        live_alerts = json.load(f)
except:
    live_alerts = []

df_live = pd.DataFrame(live_alerts)

# =========================================================
# SYSTEM OVERVIEW
# =========================================================
st.markdown("### 🔍 System Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", len(df))
col2.metric("Batch Alerts", len(alerts_df))
col3.metric("Live Alerts", len(df_live))
col4.metric(
    "Active Attacks",
    df_live["active_attack"].sum()
    if not df_live.empty and "active_attack" in df_live.columns
    else 0
)

st.divider()

# =========================================================
# LIVE REAL-TIME ALERTS (ALL SOURCES)
# =========================================================
st.markdown("### ⚡ Live Real-Time Attacks")

if not df_live.empty:
    styled_live = df_live.sort_values(
        "timestamp", ascending=False
    ).style.applymap(
        severity_color,
        subset=["alert_level"] if "alert_level" in df_live.columns else []
    )

    st.dataframe(styled_live, use_container_width=True)
else:
    st.success("No live attacks detected.")

# =========================================================
# AUDITD SECTION (RESOURCE + PERMISSION ONLY)
# =========================================================
st.divider()
st.markdown("### 🗂️ Resource & Permission Violations (auditd)")

if not df_live.empty and "source" in df_live.columns:
    audit_df = df_live[df_live["source"] == "auditd"]

    if not audit_df.empty:
        st.dataframe(
            audit_df.sort_values("timestamp", ascending=False),
            use_container_width=True
        )
    else:
        st.success("No auditd violations detected.")
else:
    st.info("Audit data not available yet.")

# =========================================================
# LIVE ATTACK TREND
# =========================================================
st.divider()
st.markdown("### 📈 Live Attack Trend")

if not df_live.empty and "timestamp" in df_live.columns:
    df_live["timestamp"] = pd.to_datetime(df_live["timestamp"], errors="coerce")
    trend = df_live.groupby(df_live["timestamp"].dt.floor("min")).size()
    st.line_chart(trend)
else:
    st.info("No live data for trend yet.")

# =========================================================
# BATCH (ML) ALERTS — DO NOT TOUCH
# =========================================================
st.divider()
st.markdown("### 🚨 Batch Detected Alerts")

if not alerts_df.empty:
    styled_batch = alerts_df.style.applymap(
        severity_color, subset=["alert_level"]
    )
    st.dataframe(styled_batch, use_container_width=True)
else:
    st.success("No batch alerts detected.")

# =========================================================
# ATTACK TYPE DISTRIBUTION (BATCH)
# =========================================================
st.divider()
st.markdown("### 🧠 Attack Type Distribution")

if not alerts_df.empty:
    st.bar_chart(alerts_df["attack_type"].value_counts())

# =========================================================
# INVESTIGATION PANEL (BATCH)
# =========================================================
st.divider()
st.markdown("### 🕵️ Investigation & Narrative")

if not alerts_df.empty:
    selected_user = st.selectbox(
        "Select a user to investigate:",
        alerts_df["user_id"].unique()
    )
    selected_alert = alerts_df[
        alerts_df["user_id"] == selected_user
    ].iloc[-1]

    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("#### 👤 Analyst Investigation Panel")
        for k, v in selected_alert.items():
            st.write(f"**{k}:** {v}")

    with col_right:
        if "narrative" in selected_alert:
            st.markdown("#### 🧾 Attack Narrative")
            st.code(selected_alert["narrative"], language="text")
else:
    st.info("No alerts available.")
