#!/bin/bash

echo "🔧 Setting up auditd rules for /secure_data monitoring..."

# Remove any existing rules for /secure_data
sudo auditctl -W /secure_data 2>/dev/null

# Add audit rule to monitor file access in /secure_data
sudo auditctl -w /secure_data -p r -k resource_access

# Add audit rule to monitor permission changes in /secure_data  
sudo auditctl -w /secure_data -p wa -k permission_change

# List current rules
echo ""
echo "✅ Audit rules configured:"
sudo auditctl -l | grep secure_data

echo ""
echo "📋 Current audit rules:"
sudo auditctl -l

echo ""
echo "✅ Setup complete!"
echo "Now run: sudo python3 pipeline/realtime_resource_monitor.py"