#!/bin/bash

# eBPF + AI GitOps Port Forward Stop Script
# Stops all kubectl port-forward processes

echo "🛑 Stopping all port forwards..."

# Kill all kubectl port-forward processes
pkill -f "kubectl port-forward" && echo "✅ All port forwards stopped" || echo "ℹ️  No port forwards were running"

echo ""
echo "💡 Use 'make port-forward' to restart port forwards"
echo "💡 Use 'make port-status' to check status"