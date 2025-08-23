#!/bin/bash

echo "🔗 Setting up port forwarding for all services..."

# Kill existing port forwards
pkill -f "kubectl port-forward" || true
sleep 2

echo ""
echo "🚀 Starting port forwards..."

# Start port forwards in background
echo "   ArgoCD UI: http://localhost:8080 (admin/admin123)"
kubectl port-forward svc/argocd-server -n argocd 8080:80 >/dev/null 2>&1 &

sleep 1
echo "   Grafana Dashboard: http://localhost:3000 (admin/admin123)"
kubectl port-forward svc/grafana -n grafana 3000:3000 >/dev/null 2>&1 &

sleep 1
echo "   Prometheus: http://localhost:9090"
kubectl port-forward svc/prometheus-server -n prometheus 9090:80 >/dev/null 2>&1 &

sleep 1
echo "   Tekton Dashboard: http://localhost:9097"
kubectl port-forward svc/tekton-dashboard -n tekton 9097:9097 >/dev/null 2>&1 &

sleep 1
echo "   ML Detector API: http://localhost:5000"
kubectl port-forward svc/ml-detector -n ebpf-security 5000:5000 >/dev/null 2>&1 &

sleep 1
echo "   eBPF Monitor: http://localhost:8800"
kubectl port-forward svc/ebpf-monitor -n ebpf-security 8800:8800 >/dev/null 2>&1 &

sleep 1
echo "   Container Registry: http://localhost:5001"
kubectl port-forward svc/registry -n registry 5001:5000 >/dev/null 2>&1 &

sleep 2
echo ""
echo "✅ All port forwards started!"
echo "💡 Use './scripts/port-stop.sh' to stop all port forwards."
echo ""
echo "🔍 Active port forwards:"
ps aux | grep 'kubectl port-forward' | grep -v grep | awk '{print "   " $11 " " $12 " " $13 " " $14}' || echo "   No active port forwards"