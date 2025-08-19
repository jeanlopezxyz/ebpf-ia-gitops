# eBPF + AI GitOps Makefile

.PHONY: help bootstrap deploy sync clean status check-deps

# Default target
help: ## Show this help message
	@echo "eBPF + AI GitOps Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

check-deps: ## Check if required tools are installed
	@echo "🔍 Checking dependencies..."
	@command -v docker >/dev/null 2>&1 || { echo "❌ Docker is not installed"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "❌ kubectl is not installed"; exit 1; }
	@command -v helm >/dev/null 2>&1 || { echo "❌ Helm is not installed"; exit 1; }
	@command -v ansible >/dev/null 2>&1 || { echo "❌ Ansible is not installed"; exit 1; }
	@command -v minikube >/dev/null 2>&1 || { echo "❌ Minikube is not installed"; exit 1; }
	@echo "✅ All dependencies are installed"

bootstrap: check-deps ## Bootstrap complete infrastructure (Minikube + ArgoCD + Apps)
	@echo "🚀 Bootstrapping eBPF + AI GitOps environment..."
	ansible-galaxy collection install kubernetes.core
	ansible-playbook -i ansible/inventory/localhost.yml ansible/bootstrap.yml

deploy: ## Deploy/update applications via ArgoCD
	@echo "🔄 Syncing ArgoCD applications..."
	argocd app sync ebpf-ai
	argocd app sync ebpf-ai-apps

status: ## Show status of all components
	@echo "📊 Component Status:"
	@echo ""
	@echo "🎯 Minikube:"
	@minikube status --profile ebpf-gitops || echo "❌ Minikube not running"
	@echo ""
	@echo "☸️  Kubernetes Nodes:"
	@kubectl get nodes 2>/dev/null || echo "❌ Cluster not accessible"
	@echo ""
	@echo "💾 Storage:"
	@kubectl get pvc -A 2>/dev/null || echo "❌ No PVCs found"
	@echo ""
	@echo "🔄 ArgoCD Applications:"
	@argocd app list 2>/dev/null || echo "❌ ArgoCD not accessible"
	@echo ""
	@echo "📦 eBPF-AI Pods:"
	@kubectl get pods -n ebpf-security 2>/dev/null || echo "❌ ebpf-security namespace not found"
	@echo ""
	@echo "🐳 Registry Status:"
	@kubectl get pods -n container-registry 2>/dev/null || echo "❌ Registry namespace not found"

sync: ## Force sync all ArgoCD applications
	@echo "🔄 Force syncing all applications..."
	argocd app sync ebpf-ai --force
	argocd app sync ebpf-ai-apps --force

logs: ## Show logs from main components
	@echo "📋 Recent logs from ML Detector:"
	kubectl logs -n ebpf-security -l app=ml-detector --tail=20 || echo "❌ ML Detector not found"
	@echo ""
	@echo "📋 Recent logs from eBPF Monitor:"
	kubectl logs -n ebpf-security -l app=ebpf-monitor --tail=20 || echo "❌ eBPF Monitor not found"

port-forward: ## Setup port forwarding for local access
	@echo "🔗 Setting up port forwarding..."
	@echo "Killing existing port forwards..."
	@pkill -f "kubectl port-forward" || true
	@sleep 2
	@echo "ArgoCD will be available at: http://localhost:8081"
	@echo "Grafana will be available at: http://localhost:3000"
	@echo "Prometheus will be available at: http://localhost:9090"
	@echo "ML Detector API will be available at: http://localhost:5000"
	@echo "eBPF Monitor metrics will be available at: http://localhost:8800"
	@echo "Tekton Dashboard will be available at: http://localhost:9097"
	@echo ""
	@echo "Starting port forwards (press Ctrl+C to stop)..."
	@kubectl port-forward svc/argocd-server -n argocd 8080:80 &
	@kubectl port-forward svc/kube-prometheus-stack-grafana -n monitoring 3000:80 &
	@kubectl port-forward svc/prometheus-server -n monitoring 9090:80 &
	@kubectl port-forward svc/ml-detector -n ebpf-security 5000:5000 &
	@kubectl port-forward svc/ebpf-monitor -n ebpf-security 8800:8800 &
	@kubectl port-forward svc/tekton-dashboard -n tekton-pipelines 9097:9097 &
	@wait

dashboard: ## Open Minikube dashboard
	minikube dashboard --profile ebpf-gitops

clean: ## Clean up everything (delete cluster and resources)
	@echo "🧹 Cleaning up eBPF + AI GitOps environment..."
	@read -p "Are you sure you want to delete everything? [y/N] " confirm && [ "$$confirm" = "y" ]
	ansible-playbook -i ansible/inventory/localhost.yml ansible/cleanup.yml

restart: clean bootstrap ## Complete restart (clean + bootstrap)

test: ## Run basic functionality tests
	@echo "🧪 Running basic tests..."
	@echo "Testing ML Detector API..."
	kubectl port-forward svc/ml-detector -n ebpf-security 5000:5000 &
	sleep 5
	curl -f http://localhost:5000/health || echo "❌ ML Detector health check failed"
	pkill -f "kubectl port-forward.*ml-detector" || true
	@echo "✅ Tests completed"

dev: ## Setup development environment with hot-reload
	@echo "🔧 Setting up development environment..."
	@echo "This will:"
	@echo "  1. Port forward all services"
	@echo "  2. Watch for changes in helm charts"
	@echo "  3. Auto-sync on changes"
	@echo ""
	make port-forward &
	watch -n 30 "argocd app sync ebpf-ai" &
	@echo "Development environment ready!"
	@echo "Edit files in helm/charts/ebpf-ai/ and they will auto-sync"
	@wait

info: ## Show access information
	@echo "🔍 eBPF + AI GitOps Access Information:"
	@echo ""
	@echo "🌐 Ingress Access (via domain names):"
	@echo "  Main Dashboard: http://ebpf-ai.local"
	@echo "  ML Detector API: http://ebpf-ai.local/api"
	@echo "  Grafana: http://ebpf-ai.local/grafana (admin/admin123)"
	@echo "  Prometheus: http://ebpf-ai.local/prometheus"
	@echo "  ArgoCD: http://ebpf-ai.local/argocd (admin/admin123)"
	@echo "  Registry: http://registry.local"
	@echo ""
	@echo "🔗 Direct LoadBalancer Access:"
	@echo "  ArgoCD: http://$(shell kubectl get svc argocd-server -n argocd -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo 'pending')"
	@echo "  Grafana: http://$(shell kubectl get svc kube-prometheus-stack-grafana -n monitoring -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo 'pending')"
	@echo "  NGINX: http://$(shell kubectl get svc ingress-nginx-controller -n ingress-nginx -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo 'pending')"
	@echo ""
	@echo "🐳 Container Registry:"
	@echo "  Registry: $(shell minikube ip --profile ebpf-gitops 2>/dev/null || echo 'pending'):30050"
	@echo "  Usage: docker tag image:latest $(shell minikube ip --profile ebpf-gitops 2>/dev/null || echo 'MINIKUBE_IP'):30050/image:latest"
	@echo ""
	@echo "🚀 Quick Commands:"
	@echo "  make port-forward  # Local access via port forwarding"
	@echo "  make status        # Check system status"
	@echo "  make logs          # View application logs"
	@echo "  make sync          # Force sync GitOps"
