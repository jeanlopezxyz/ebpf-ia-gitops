#!/bin/bash

# eBPF + AI GitOps Port Forward Script
# Sets up port forwarding for all key services

export KUBECONFIG=~/.kube/config-kubeadm

echo "🔗 Setting up port forwarding for all services..."

# Kill any existing port forwards
echo "Killing existing port forwards..."
pkill -f "kubectl port-forward" || true
sleep 2

echo ""
echo "🚀 Starting port forwards..."

# ArgoCD
echo "   ArgoCD UI: http://localhost:8080 (admin/admin123)"
kubectl port-forward svc/argocd-server -n argocd 8080:80 >/dev/null 2>&1 &

# Grafana  
echo "   Grafana Dashboard: http://localhost:3000 (admin/admin123)"
kubectl port-forward svc/grafana -n grafana 3000:3000 >/dev/null 2>&1 &

# Prometheus
echo "   Prometheus: http://localhost:9090"
kubectl port-forward svc/prometheus-server -n prometheus 9090:80 >/dev/null 2>&1 &

# Registry
echo "   Container Registry: http://localhost:5001"
kubectl port-forward svc/registry -n registry 5001:5000 >/dev/null 2>&1 &

# ML Detector
echo "   ML Detector API: http://localhost:5000"
kubectl port-forward svc/ml-detector -n ebpf-security 5000:5000 >/dev/null 2>&1 &

# eBPF Monitor
echo "   eBPF Monitor: http://localhost:8800"
kubectl port-forward svc/ebpf-monitor -n ebpf-security 8800:8800 >/dev/null 2>&1 &

# Tekton Dashboard
echo "   Tekton Dashboard: http://localhost:9097"
kubectl port-forward svc/tekton-dashboard -n tekton 9097:9097 >/dev/null 2>&1 &

sleep 3

echo ""
echo "✅ All port forwards active!"
echo ""
echo "🌐 Access URLs:"
echo "   ArgoCD:      http://localhost:8080 (admin/admin123)"
echo "   Grafana:     http://localhost:3000 (admin/admin123)" 
echo "   Prometheus:  http://localhost:9090"
echo "   Registry:    http://localhost:5001"
echo "   ML Detector: http://localhost:5000"
echo "   eBPF Monitor: http://localhost:8800"
echo "   Tekton:      http://localhost:9097"
echo ""
echo "💡 Use 'make port-stop' to stop all port forwards"
echo "💡 Use 'make port-status' to check status"