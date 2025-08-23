#!/bin/bash

echo "🛑 Stopping all port forwards..."
pkill -f "kubectl port-forward" || true
echo "✅ All port forwards stopped."