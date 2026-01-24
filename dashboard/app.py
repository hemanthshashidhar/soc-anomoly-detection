import streamlit as st
import pandas as pd
import json
from streamlit_autorefresh import st_autorefresh
from ml.detect import run_detection_with_alerts

# ---------------- AUTO REFRESH ----------------
#st_autorefresh(interval=5000, key="live_refresh")

st.set_page_config(page_title="Identity Threat SOC", layout="wide")

# ---------------- UI HEADER ----------------
st.markdown("""
<h1 style='color:#00FFAA; text-align:center;'>🛡️ Identity Threat Intelligence SOC</h1>
<h4 style='text-align:center; color:#888;'>AI-Powered Identity Threat Detection & Real-Time Monitoring</h4>
""", unsafe_allow_html=True)

# ---------------- SEVERITY COLOR FUNCTION ----------------
def severity_color(level):
    if level == "CRITICAL":
        return "background-color: #ff4d4d; color: white;"
    elif level == "HIGH":
        return "background-color: #ff944d; color: black;"
    elif level == "MEDIUM":
        return "background-color: #ffe066; color: black;"
    else:
        return ""

# ---------------- LOAD BATCH ALERTS ----------------
df, alerts = run_detection_with_alerts()
alerts_df = pd.DataFrame(alerts)

# ---------------- LOAD LIVE ALERTS ----------------
LIVE_ALERTS_FILE = "data/live_alerts.json"
try:
    with open(LIVE_ALERTS_FILE, "r") as f:
        live_alerts = json.load(f)
except:
    live_alerts = []

# ---------------- SYSTEM OVERVIEW ----------------
st.markdown("### 🔍 System Overview")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", len(df))
col2.metric("Batch Alerts", len(alerts_df))
col3.metric("Live Alerts", len(live_alerts))
col4.metric("Accounts Under Attack", alerts_df["active_attack"].sum() if not alerts_df.empty else 0)

st.divider()

# ---------------- LIVE REAL-TIME ALERTS ----------------
st.markdown("### ⚡ Live Real-Time Attacks")

if live_alerts:
    df_live = pd.DataFrame(live_alerts[::-1])

    if "alert_level" in df_live.columns:
        styled = df_live.style.applymap(severity_color, subset=["alert_level"])
        st.dataframe(styled, use_container_width=True)
    else:
        st.dataframe(df_live, use_container_width=True)
else:
    st.success("No live attacks detected.")

# ---------------- LIVE ATTACK TREND ----------------
st.markdown("### 📈 Live Attack Trend")

if live_alerts:
    df_live["timestamp"] = pd.to_datetime(df_live["timestamp"])
    trend = df_live.groupby(df_live["timestamp"].dt.floor("min")).size()
    st.line_chart(trend)
else:
    st.info("No live data for graph yet.")

st.divider()

# ---------------- BATCH ALERTS ----------------
st.markdown("### 🚨 Batch Detected Alerts")

if not alerts_df.empty:
    styled_batch = alerts_df.style.applymap(severity_color, subset=["alert_level"])
    st.dataframe(styled_batch, use_container_width=True)
else:
    st.success("No batch alerts detected.")

st.divider()

# ---------------- ATTACK TYPE DISTRIBUTION ----------------
st.markdown("### 🧠 Attack Type Distribution")
if not alerts_df.empty:
    st.bar_chart(alerts_df["attack_type"].value_counts())

st.divider()

st.markdown("### 🕵️ Investigation & Narrative")

if not alerts_df.empty:
    selected_user = st.selectbox("Select a user to investigate:", alerts_df["user_id"].unique())
    selected_alert = alerts_df[alerts_df["user_id"] == selected_user].iloc[-1]

    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("#### 👤 Analyst Investigation Panel")
        st.write(f"**User:** {selected_user}")
        st.write(f"**Attack Type:** {selected_alert['attack_type']}")
        st.write(f"**Alert Level:** {selected_alert['alert_level']}")
        st.write(f"**Risk Score:** {selected_alert['risk_score']}")
        st.write(f"**Country:** {selected_alert['country']}")
        st.write(f"**Resource:** {selected_alert['resource']}")
        st.write(f"**Trend:** {selected_alert['risk_trend']}")
        st.write(f"**Active Attack:** {selected_alert['active_attack']}")

    with col_right:
        st.markdown("#### 🧾 Attack Narrative")
        st.code(selected_alert["narrative"], language="text")
else:
    st.info("No alerts available.")
