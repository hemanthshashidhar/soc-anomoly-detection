import sys
import os
import json
from pathlib import Path
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from streamlit_autorefresh import st_autorefresh
from ml.detect import run_detection_with_alerts

# =========================================================
# PATH SETUP
# =========================================================
BASE_DIR = Path(__file__).resolve().parent.parent
LIVE_ALERTS_FILE = BASE_DIR / "data" / "live_alerts.json"

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="Identity Threat SOC", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================================================
# CUSTOM CSS FOR TRANSPARENT CHARTS
# =========================================================
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
    }
    .section-header {
        color: #1e3c72;
        border-bottom: 2px solid #2a5298;
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
    }
    .stPlotlyChart > div {
        background-color: transparent !important;
    }
    .css-1d391kg {
        background-color: transparent;
    }
</style>
""", unsafe_allow_html=True)

# =========================================================
# UTILITY FUNCTIONS
# =========================================================
def severity_color(level):
    colors = {
        "CRITICAL": "#f44336",
        "HIGH": "#ff9800", 
        "MEDIUM": "#ffeb3b",
        "LOW": "#4caf50"
    }
    return colors.get(level, "#9e9e9e")

def normalize_risk(val):
    try:
        return round(val / 100, 2) if val > 1 else round(val, 2)
    except:
        return val

def highlight_alert_level(df):
    """Apply color highlighting to alert level column with borders"""
    def color_alert_level(val):
        if val == 'CRITICAL':
            return 'background-color: #ffebee; color: #d32f2f; font-weight: bold; border: 2px solid #d32f2f; border-radius: 4px; padding: 4px;'
        elif val == 'HIGH':
            return 'background-color: #fff3e0; color: #f57c00; font-weight: bold; border: 2px solid #f57c00; border-radius: 4px; padding: 4px;'
        elif val == 'MEDIUM':
            return 'background-color: #fffde7; color: #f9a825; font-weight: bold; border: 2px solid #f9a825; border-radius: 4px; padding: 4px;'
        return ''
    
    if 'alert_level' in df.columns:
        return df.style.applymap(color_alert_level, subset=['alert_level'])
    return df

def format_timestamp(ts):
    try:
        if isinstance(ts, str):
            dt = pd.to_datetime(ts)
        else:
            dt = ts
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(ts)

# =========================================================
# DATA LOADING
# =========================================================
@st.cache_data(ttl=2)
def load_live_alerts():
    try:
        st.sidebar.write(f"📂 Looking for file: {LIVE_ALERTS_FILE}")
        st.sidebar.write(f"📍 File exists: {LIVE_ALERTS_FILE.exists()}")
        
        if not LIVE_ALERTS_FILE.exists():
            st.sidebar.error("Live alerts file not found!")
            return pd.DataFrame()
        
        # Debug: Show file path and modification time
        mod_time = datetime.fromtimestamp(LIVE_ALERTS_FILE.stat().st_mtime)
        file_size = LIVE_ALERTS_FILE.stat().st_size
        st.sidebar.write(f"📁 Data file: {LIVE_ALERTS_FILE.name}")
        st.sidebar.write(f"🕒 Last modified: {mod_time.strftime('%H:%M:%S')}")
        st.sidebar.write(f"📏 File size: {file_size} bytes")
        
        with open(LIVE_ALERTS_FILE, "r") as f:
            content = f.read()
            st.sidebar.write(f"📄 File content length: {len(content)} chars")
            
        with open(LIVE_ALERTS_FILE, "r") as f:
            live_alerts = json.load(f)
        
        st.sidebar.write(f"📊 Total alerts loaded: {len(live_alerts)}")
        
        if len(live_alerts) > 0:
            st.sidebar.write(f"🔍 Sample alert keys: {list(live_alerts[0].keys())}")
        
        df_live = pd.DataFrame(live_alerts)
        if not df_live.empty and "risk_score" in df_live.columns:
            df_live["risk_score"] = df_live["risk_score"].apply(normalize_risk)
        if not df_live.empty and "timestamp" in df_live.columns:
            df_live["timestamp"] = pd.to_datetime(df_live["timestamp"], errors="coerce")
        
        st.sidebar.write(f"✅ DataFrame shape: {df_live.shape}")
        return df_live
    except Exception as e:
        st.sidebar.error(f"❌ Error loading live alerts: {str(e)}")
        st.sidebar.write(f"🔧 Exception type: {type(e).__name__}")
        import traceback
        st.sidebar.text(traceback.format_exc())
        return pd.DataFrame()

@st.cache_data(ttl=30)
def load_batch_alerts():
    try:
        df, alerts = run_detection_with_alerts()
        alerts_df = pd.DataFrame(alerts) if alerts else pd.DataFrame()
        return df, alerts_df
    except Exception as e:
        st.error(f"Error loading batch alerts: {str(e)}")
        return pd.DataFrame(), pd.DataFrame()

# =========================================================
# SIDEBAR NAVIGATION
# =========================================================
st.sidebar.markdown("""
<div style='text-align: center; padding: 1rem;'>
    <h2>🛡️ SOC Dashboard</h2>
</div>
""", unsafe_allow_html=True)

page = st.sidebar.selectbox(
    "Select Dashboard View",
    ["🔴 Real-Time Monitoring", "📊 Batch Analysis & Investigation"]
)

# Auto-refresh for real-time page
if page == "🔴 Real-Time Monitoring":
    st_autorefresh(interval=5000, key="realtime_refresh")
    # Auto-clear cache on refresh
    st.cache_data.clear()

# Load data
df_live = load_live_alerts()

# Debug section
st.sidebar.markdown("---")
st.sidebar.markdown("### 🔧 Debug Info")
if not df_live.empty:
    st.sidebar.write(f"DataFrame columns: {list(df_live.columns)}")
    st.sidebar.write(f"Recent alerts: {len(df_live[df_live['timestamp'] > (datetime.now() - timedelta(hours=1))])}" if 'timestamp' in df_live.columns else "No timestamp column")
else:
    st.sidebar.write("DataFrame is empty!")

# =========================================================
# PAGE 1: REAL-TIME MONITORING
# =========================================================
if page == "🔴 Real-Time Monitoring":
    st.markdown("""
    <div class="main-header">
        <h1 style='color: white; margin: 0;'>🔴 Real-Time Threat Monitoring</h1>
        <p style='color: #e3f2fd; margin: 0.5rem 0 0 0;'>Live Attack Detection & Resource Monitoring</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Debug: Show raw data
    with st.expander("🔧 Debug: Raw Data Viewer", expanded=False):
        st.write(f"**Data loaded:** {not df_live.empty}")
        st.write(f"**Rows:** {len(df_live)}")
        if not df_live.empty:
            st.write(f"**Columns:** {list(df_live.columns)}")
            st.write("**Sample data:**")
            st.dataframe(df_live.head(3))
        else:
            st.write("No data loaded - check sidebar for errors")
    
    # System Status - Show only SSH and Resource Violations
    col1, col2 = st.columns(2)
    
    # Filter for recent alerts only (last 1 hour)
    recent_df = df_live.copy()
    if not recent_df.empty and 'timestamp' in recent_df.columns:
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_df = recent_df[recent_df['timestamp'] > one_hour_ago]
    
    with col1:
        ssh_attacks = 0
        if not recent_df.empty and "source" in recent_df.columns:
            ssh_attacks = len(recent_df[recent_df["source"] == "ssh"])
        st.metric("🔐 SSH Attacks (1h)", ssh_attacks,
                 delta="Active" if ssh_attacks > 0 else "Secure")
    
    with col2:
        audit_violations = 0
        if not recent_df.empty and "source" in recent_df.columns:
            audit_violations = len(recent_df[recent_df["source"] == "auditd"])
        st.metric("🗂️ Resource Violations (1h)", audit_violations,
                 delta="Active" if audit_violations > 0 else "Secure")
    
    st.divider()
    
    # Real-Time Attack Timeline - Show only recent data
    st.markdown('<h2 class="section-header">📈 Live Attack Timeline</h2>', unsafe_allow_html=True)
    
    if not recent_df.empty and 'timestamp' in recent_df.columns:
        df_live_copy = recent_df.copy()
        
        # Ensure alert_level exists
        if 'alert_level' not in df_live_copy.columns:
            df_live_copy['alert_level'] = 'HIGH'
        
        df_live_copy['minute'] = df_live_copy['timestamp'].dt.floor('1min')  # Changed to 1-min for more granular view
        
        # Count attacks by minute and source
        timeline_by_source = df_live_copy.groupby(['minute', 'source']).size().reset_index(name='count')
        
        if not timeline_by_source.empty:
            fig, ax = plt.subplots(figsize=(12, 4))
            fig.patch.set_alpha(0.0)
            ax.patch.set_alpha(0.0)
            
            # Plot SSH attacks
            ssh_data = timeline_by_source[timeline_by_source['source'] == 'ssh']
            if not ssh_data.empty:
                ax.plot(ssh_data['minute'], ssh_data['count'], 
                       marker='o', linewidth=3, label='SSH Attacks',
                       color='#ff6b6b', markersize=8)
            
            # Plot Resource violations
            audit_data = timeline_by_source[timeline_by_source['source'] == 'auditd']
            if not audit_data.empty:
                ax.plot(audit_data['minute'], audit_data['count'], 
                       marker='s', linewidth=3, label='Resource Violations',
                       color='#ffa500', markersize=8)
            
            ax.set_title('Real-Time Attack Timeline (1-min intervals)', fontsize=16, fontweight='bold', color='white')
            ax.set_xlabel('Time', color='white', fontsize=12)
            ax.set_ylabel('Number of Attacks', color='white', fontsize=12)
            ax.tick_params(colors='white', labelsize=10)
            for label in ax.get_xticklabels() + ax.get_yticklabels():
                label.set_color('white')
            ax.legend(loc='upper left', fontsize=12)
            ax.grid(True, alpha=0.3, color='white')
            plt.xticks(rotation=45)
            plt.tight_layout()
            st.pyplot(fig, transparent=True)
        else:
            st.info("No timeline data available.")
    else:
        st.info("No real-time data available.")
    
    st.divider()
    
    # Live Alerts Table
    st.markdown('<h2 class="section-header">⚡ Live Real-Time Alerts</h2>', unsafe_allow_html=True)
    
    if not df_live.empty:
        # Quick filters
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.selectbox("Severity", ["All"] + list(df_live['alert_level'].unique()) if 'alert_level' in df_live.columns else ["All"])
        with col2:
            source_filter = st.selectbox("Source", ["All"] + list(df_live['source'].unique()) if 'source' in df_live.columns else ["All"])
        
        # Apply filters
        filtered_df = df_live.copy()
        if severity_filter != "All":
            filtered_df = filtered_df[filtered_df['alert_level'] == severity_filter]
        if source_filter != "All":
            filtered_df = filtered_df[filtered_df['source'] == source_filter]
        
        if not filtered_df.empty:
            display_df = filtered_df.copy()
            if 'timestamp' in display_df.columns:
                display_df['timestamp'] = display_df['timestamp'].apply(format_timestamp)
            
            # Ensure all required columns exist
            if 'risk_score' not in display_df.columns:
                display_df['risk_score'] = display_df.apply(lambda row: 
                    0.95 if row.get('alert_level') == 'CRITICAL' else
                    0.80 if row.get('alert_level') == 'HIGH' else
                    0.60 if row.get('alert_level') == 'MEDIUM' else 0.40, axis=1)
            
            if 'reasons' not in display_df.columns:
                display_df['reasons'] = display_df.apply(lambda row: 
                    f"{row.get('attack_type', 'Security event')} from {row.get('source', 'system')}", axis=1)
            
            if 'narrative' not in display_df.columns:
                display_df['narrative'] = display_df.apply(lambda row: 
                    f"Security alert: {row.get('attack_type', 'Unknown')} detected for user {row.get('user_id', 'unknown')} from source {row.get('source', 'system')}", axis=1)
            
            display_df = display_df.sort_values('timestamp', ascending=False)
            styled_df = highlight_alert_level(display_df)
            st.dataframe(styled_df, use_container_width=True, height=400)
        else:
            st.success("No alerts match the current filters.")
    else:
        st.success("No live attacks detected. System is secure.")
    
    st.divider()
    
    # Resource & Permission Violations
    st.markdown('<h2 class="section-header">🗂️ Resource & Permission Violations</h2>', unsafe_allow_html=True)
    
    if not df_live.empty and "source" in df_live.columns:
        audit_df = df_live[df_live["source"] == "auditd"].copy()
        if not audit_df.empty:
            # Format timestamp
            if 'timestamp' in audit_df.columns:
                audit_df['timestamp'] = audit_df['timestamp'].apply(format_timestamp)
            
            # Select and reorder columns for display
            display_cols = ['timestamp', 'user_id', 'resource', 'attack_type', 'alert_level', 'risk_score']
            audit_display = audit_df[[col for col in display_cols if col in audit_df.columns]]
            
            styled_audit = highlight_alert_level(audit_display.sort_values("timestamp", ascending=False))
            st.dataframe(styled_audit, use_container_width=True, height=300)
        else:
            st.success("No resource violations detected.")
    else:
        st.info("Audit data not available.")
    
    st.divider()
    
    # SSH Attacks
    st.markdown('<h2 class="section-header">🔐 Real-Time SSH Attacks</h2>', unsafe_allow_html=True)
    
    if not df_live.empty and "source" in df_live.columns:
        ssh_df = df_live[df_live["source"] == "ssh"].copy()
        if not ssh_df.empty:
            # Format timestamp
            if 'timestamp' in ssh_df.columns:
                ssh_df['timestamp'] = ssh_df['timestamp'].apply(format_timestamp)
            
            # Select and reorder columns for display
            display_cols = ['timestamp', 'user_id', 'ip', 'attack_type', 'alert_level', 'risk_score']
            ssh_display = ssh_df[[col for col in display_cols if col in ssh_df.columns]]
            
            styled_ssh = highlight_alert_level(ssh_display.sort_values("timestamp", ascending=False))
            st.dataframe(styled_ssh, use_container_width=True, height=300)
        else:
            st.success("No SSH attacks detected.")
    else:
        st.info("SSH data not available.")
    
    st.divider()
    
    # ML Model Performance
    st.markdown('<h2 class="section-header">🧠 ML Model Performance</h2>', unsafe_allow_html=True)
    
    METRICS_FILE = BASE_DIR / "ml" / "models" / "isolation_forest_metrics.json"
    
    try:
        with open(METRICS_FILE, "r") as f:
            model_metrics = json.load(f)
        
        if model_metrics:
            col1, col2 = st.columns([2, 2])
            
            with col1:
                metrics_names = ["Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"]
                metrics_values = [
                    model_metrics.get("accuracy", 0),
                    model_metrics.get("precision", 0),
                    model_metrics.get("recall", 0),
                    model_metrics.get("f1_score", 0),
                    model_metrics.get("roc_auc", 0)
                ]
                
                angles = np.linspace(0, 2 * np.pi, len(metrics_names), endpoint=False).tolist()
                metrics_values += metrics_values[:1]
                angles += angles[:1]
                
                fig, ax = plt.subplots(figsize=(4, 4), subplot_kw=dict(projection='polar'))
                fig.patch.set_alpha(0.0)
                ax.patch.set_alpha(0.0)
                
                ax.plot(angles, metrics_values, 'o-', linewidth=3, color='#2a5298', markersize=8)
                ax.fill(angles, metrics_values, alpha=0.25, color='#2a5298')
                ax.set_xticks(angles[:-1])
                ax.set_xticklabels(metrics_names)
                ax.set_ylim(0, 1)
                ax.set_title('Model Performance', fontsize=16, fontweight='bold', pad=20, color='white')
                ax.tick_params(colors='white')
                ax.grid(True, alpha=0.3)
                
                plt.tight_layout()
                st.pyplot(fig, transparent=True)
            
            with col2:
                st.markdown("#### Performance Metrics")
                for name, value in zip(metrics_names[:-1], metrics_values[:-1]):
                    st.metric(name, f"{value:.3f}")
        else:
            st.info("Model metrics not available.")
    except FileNotFoundError:
        st.warning("Model metrics file not found.")
    except Exception as e:
        st.error(f"Error loading model metrics: {str(e)}")

# =========================================================
# PAGE 2: BATCH ANALYSIS & INVESTIGATION
# =========================================================
elif page == "📊 Batch Analysis & Investigation":
    st.markdown("""
    <div class="main-header">
        <h1 style='color: white; margin: 0;'>📊 Batch Analysis & Investigation</h1>
        <p style='color: #e3f2fd; margin: 0.5rem 0 0 0;'>ML Detection Results & Threat Intelligence</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Load batch data
    df, alerts_df = load_batch_alerts()
    
    # System Overview
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_events = len(df) if not df.empty else 0
        st.metric("📈 Total Events", f"{total_events:,}")
    
    with col2:
        batch_alerts = len(alerts_df) if not alerts_df.empty else 0
        st.metric("🚨 Batch Alerts", batch_alerts)
    
    with col3:
        anomalies = 0
        if not df.empty and 'ml_anomaly' in df.columns:
            anomalies = df['ml_anomaly'].sum()
        st.metric("🔍 ML Anomalies", anomalies)
    
    st.divider()
    
    # Attack Analysis
    st.markdown('<h2 class="section-header">🔍 Attack Analysis</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        if not df_live.empty and 'attack_type' in df_live.columns:
            attack_counts = df_live['attack_type'].value_counts().head(8)
            
            fig, ax = plt.subplots(figsize=(10, 6))
            fig.patch.set_alpha(0.0)
            ax.patch.set_alpha(0.0)
            
            bars = ax.barh(range(len(attack_counts)), attack_counts.values, 
                          color='#ff6b6b', alpha=0.8)
            
            ax.set_yticks(range(len(attack_counts)))
            ax.set_yticklabels(attack_counts.index)
            ax.set_xlabel('Number of Attacks', color='white')
            ax.set_title('Top Attack Types', fontsize=16, fontweight='bold', color='white')
            ax.tick_params(colors='white')
            
            for i, bar in enumerate(bars):
                width = bar.get_width()
                ax.text(width + 0.1, bar.get_y() + bar.get_height()/2, 
                       f'{int(width)}', ha='left', va='center')
            
            plt.tight_layout()
            st.pyplot(fig, transparent=True)
    
    with col2:
        if not alerts_df.empty and 'attack_type' in alerts_df.columns:
            batch_attacks = alerts_df['attack_type'].value_counts()
            
            fig, ax = plt.subplots(figsize=(8, 8))
            fig.patch.set_alpha(0.0)
            ax.patch.set_alpha(0.0)
            
            colors = plt.cm.Set3(np.linspace(0, 1, len(batch_attacks)))
            wedges, texts, autotexts = ax.pie(batch_attacks.values, 
                                             labels=batch_attacks.index,
                                             colors=colors,
                                             autopct='%1.1f%%',
                                             startangle=90)
            
            ax.set_title('Batch Alert Distribution', fontsize=16, fontweight='bold', color='white')
            plt.tight_layout()
            st.pyplot(fig, transparent=True)
    
    st.divider()
    
    # Batch Alerts Table
    st.markdown('<h2 class="section-header">🚨 Batch Detection Results</h2>', unsafe_allow_html=True)
    
    if not alerts_df.empty:
        display_batch = alerts_df.copy()
        if 'risk_score' in display_batch.columns:
            display_batch['risk_score'] = display_batch['risk_score'].apply(lambda x: f"{x:.2f}")
        styled_batch = highlight_alert_level(display_batch)
        st.dataframe(styled_batch, use_container_width=True, height=300)
    else:
        st.success("No batch alerts detected.")
    
    st.divider()
    
    # Investigation Panel
    st.markdown('<h2 class="section-header">🕵️ Investigation & Narrative</h2>', unsafe_allow_html=True)
    
    if not alerts_df.empty and 'user_id' in alerts_df.columns:
        selected_user = st.selectbox("Select user to investigate:", alerts_df["user_id"].unique())
        
        user_alerts = alerts_df[alerts_df["user_id"] == selected_user]
        if not user_alerts.empty:
            selected_alert = user_alerts.iloc[-1]
            
            col1, col2 = st.columns([1, 1])
            
            with col1:
                st.markdown("#### 👤 User Profile")
                info_data = {
                    "User ID": selected_alert.get("user_id", "N/A"),
                    "Risk Score": f"{selected_alert.get('risk_score', 0):.2f}",
                    "Alert Level": selected_alert.get("alert_level", "N/A"),
                    "Attack Type": selected_alert.get("attack_type", "N/A"),
                    "Country": selected_alert.get("country", "N/A"),
                    "Role": selected_alert.get("role", "N/A")
                }
                
                for key, value in info_data.items():
                    st.write(f"**{key}:** {value}")
            
            with col2:
                st.markdown("#### 🧾 Attack Narrative")
                narrative = selected_alert.get("narrative", "No narrative available.")
                st.text_area("AI Analysis", value=narrative, height=200, disabled=True)
    else:
        st.info("No investigation data available.")

# Footer
st.divider()
st.markdown(f"""
<div style='text-align: center; color: #666; padding: 1rem;'>
    <p>🛡️ Identity Threat SOC | Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Page: {page}</p>
</div>
""", unsafe_allow_html=True)