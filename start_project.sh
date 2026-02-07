#!/bin/bash

echo "🚀 Starting AI-Based Identity Threat Detection System..."
echo ""

# Get project directory
PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$PROJECT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -q -r requirements.txt

# Clean alerts file
echo "🧹 Cleaning live alerts file..."
echo "[]" > data/live_alerts.json

echo ""
echo "✅ Setup complete!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Starting Components (Open in separate terminals):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1️⃣  DASHBOARD (Main UI):"
echo "   streamlit run dashboard/app.py"
echo ""
echo "2️⃣  SSH MONITOR (Real-time SSH attack detection):"
echo "   sudo python3 realtime_monitor.py"
echo ""
echo "3️⃣  RESOURCE MONITOR (File access monitoring):"
echo "   sudo python3 pipeline/realtime_resource_monitor.py"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🎯 Quick Start:"
echo "   Run this in Terminal 1: streamlit run dashboard/app.py"
echo "   Run this in Terminal 2: sudo python3 realtime_monitor.py"
echo "   Run this in Terminal 3: sudo python3 pipeline/realtime_resource_monitor.py"
echo ""
echo "🌐 Dashboard will open at: http://localhost:8501"
echo ""
