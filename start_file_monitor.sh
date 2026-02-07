#!/bin/bash

echo "🔧 AI-Based Identity Threat Detection - File Access Monitor Setup"
echo "=================================================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run with sudo: sudo ./start_file_monitor.sh"
    exit 1
fi

echo "Step 1: Setting up audit rules..."
# Remove existing rules
auditctl -W /secure_data 2>/dev/null

# Add new rules
auditctl -w /secure_data -p r -k resource_access
auditctl -w /secure_data -p wa -k permission_change

echo "✅ Audit rules configured:"
auditctl -l | grep secure_data

echo ""
echo "Step 2: Starting file access monitor..."
echo "Monitor will detect when you access /secure_data files"
echo ""
echo "📋 Test it by running in another terminal:"
echo "   sudo less /secure_data/hr.txt"
echo "   sudo cat /secure_data/hr.txt"
echo ""
echo "Press Ctrl+C to stop monitoring"
echo "=================================================================="
echo ""

# Start the monitor
python3 pipeline/realtime_resource_monitor.py