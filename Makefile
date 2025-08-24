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

bootstrap: check-deps ## Bootstrap complete infrastructure (Minikube + ArgoCD + Auto-deploy Apps)
	@echo "🚀 Bootstrapping eBPF + AI GitOps environment..."
	@echo "This will:"
	@echo "  1. Create Minikube cluster (ebpf-ia profile)"
	@echo "  2. Install Cilium CNI with eBPF"
	@echo "  3. Install ArgoCD GitOps"
	@echo "  4. Auto-create and sync all applications"
	@echo "  5. Wait for applications to be healthy"
	@echo ""
	ansible-galaxy collection install kubernetes.core
	ansible-playbook -i ansible/inventory/localhost.yml ansible/bootstrap.yml
	@echo ""
	@echo "✅ Bootstrap complete! Run 'make port-forward' to access services"

bootstrap-kubeadm: check-deps ## Bootstrap with kubeadm + KVM (production-like)
	@echo "🚀 Bootstrapping eBPF + AI GitOps with kubeadm + KVM..."
	@echo "This will:"
	@echo "  1. Create KVM virtual machine"
	@echo "  2. Install Ubuntu + kubeadm single-node cluster"
	@echo "  3. Install Cilium CNI with eBPF"
	@echo "  4. Install ArgoCD GitOps"
	@echo "  5. Auto-create and sync all applications"
	@echo ""
	ansible-galaxy collection install kubernetes.core
	ansible-playbook -i ansible/inventory/localhost.yml ansible/bootstrap.yml -e cluster_method=kubeadm
	@echo ""
	@echo "✅ Kubeadm bootstrap complete! Export KUBECONFIG=~/.kube/config-kubeadm"

deploy: ## Deploy/update applications via ArgoCD (manual sync)
	@echo "🔄 Manually syncing ArgoCD applications..."
	@kubectl port-forward svc/argocd-server -n argocd 8080:80 &
	@PORT_PID=$$!; \
	sleep 5; \
	argocd login localhost:8080 --username admin --password admin123 --insecure; \
	argocd app sync app-of-apps --force; \
	argocd app sync ebpf-ai --force; \
	kill $$PORT_PID || true

status: ## Show status of all components
	@echo "📊 Component Status:"
	@echo ""
	@echo "🎯 Minikube:"
	@minikube status --profile ebpf-ia || echo "❌ Minikube not running"
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
	@kubectl get pods -n registry 2>/dev/null || echo "❌ Registry namespace not found"

sync: ## Force sync all ArgoCD applications
	@echo "🔄 Force syncing all applications..."
	argocd app sync ebpf-ai --force
	argocd app sync app-of-apps --force

logs: ## Show logs from main components
	@echo "📋 Recent logs from ML Detector:"
	kubectl logs -n ebpf-security -l app=ml-detector --tail=20 || echo "❌ ML Detector not found"
	@echo ""
	@echo "📋 Recent logs from eBPF Monitor:"
	kubectl logs -n ebpf-security -l app=ebpf-monitor --tail=20 || echo "❌ eBPF Monitor not found"

port-forward-argocd: ## Setup port forwarding for ArgoCD only
	@echo "🔗 Setting up port forwarding for ArgoCD..."
	@echo "Killing existing port forwards..."
	@pkill -f "kubectl port-forward" || true
	@sleep 2
	@echo ""
	@echo "🚀 Starting ArgoCD port forward..."
	@echo "   ArgoCD UI: http://localhost:8080 (admin/admin123)"
	@kubectl port-forward svc/argocd-server -n argocd 8080:80 >/dev/null 2>&1 &
	@sleep 2
	@echo ""
	@echo "✅ ArgoCD port forward active!"
	@echo "💡 Use 'pkill -f kubectl port-forward' to stop manually."

port-forward: ## Setup port forwarding for all services
	./scripts/port-forward.sh

port-stop: ## Stop all port forwards
	./scripts/port-stop.sh

port-status: ## Show status of port forwards
	@echo "🔍 Active port forwards:"
	@ps aux | grep 'kubectl port-forward' | grep -v grep | awk '{print "   " $$11 " " $$12 " " $$13 " " $$14}' || echo "   No active port forwards"

dashboard: ## Open Minikube dashboard
	minikube dashboard --profile ebpf-ia

threats: ## Open threat detection dashboard via port-forward
	@echo "🚨 Threat Detection Dashboard..."
	@echo "First deploy applications with: make sync"
	@echo "Then access via ArgoCD: https://localhost:8080"
	@echo "Login: admin / admin123"

clean: ## Clean up everything (delete cluster and resources)
	@echo "🧹 Cleaning up eBPF + AI GitOps environment..."
	@read -p "Are you sure you want to delete everything? [y/N] " confirm && [ "$$confirm" = "y" ]
	ansible-playbook -i ansible/inventory/localhost.yml ansible/cleanup.yml

clean-kubeadm: ## Clean up kubeadm KVM environment
	@echo "🧹 Cleaning up kubeadm + KVM environment..."
	@read -p "Are you sure you want to delete the KVM cluster? [y/N] " confirm && [ "$$confirm" = "y" ]
	@sudo virsh destroy ebpf-kvm-node || true
	@sudo virsh undefine ebpf-kvm-node || true
	@rm -f ~/.kube/config-kubeadm || true
	@echo "✅ Kubeadm environment cleanup complete"

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
	@echo "🌐 NodePort Access (direct via Minikube IP):"
	@MINIKUBE_IP=$$(minikube ip -p ebpf-ia 2>/dev/null || echo 'pending'); \
	echo "  Grafana Dashboard: http://$$MINIKUBE_IP:30300 (admin/admin123)"; \
	echo "  Container Registry: http://$$MINIKUBE_IP:30050"; \
	echo "  ArgoCD UI: http://$$MINIKUBE_IP:31055 (admin/admin123)"; \
	echo "  Tekton Dashboard: http://$$MINIKUBE_IP:30097"
	@echo ""
	@echo "🔗 Port Forward Access (RECOMMENDED - always works):"
	@echo "  Run: make port-forward"
	@echo "  Then access:"
	@echo "    Grafana Dashboard: http://localhost:3000 (admin/admin123)"
	@echo "    Prometheus: http://localhost:9090"
	@echo "    ArgoCD UI: http://localhost:8080 (admin/admin123)"
	@echo "    ML Detector API: http://localhost:5000"
	@echo "    eBPF Monitor: http://localhost:8800"
	@echo "    Tekton Dashboard: http://localhost:9097"
	@echo "    Container Registry: http://localhost:5001"
	@echo ""
	@echo "🚨 Threat Detection Dashboard:"
	@echo "  Run: make threats  # Port-forwards and opens Grafana threat dashboard"
	@echo ""
	@echo "🐳 Container Registry (via port-forward):"
	@echo "  docker tag image:latest localhost:5001/image:latest"
	@echo "  docker push localhost:5001/image:latest"
	@echo ""
	@echo "🚀 Quick Commands:"
	@echo "  make port-forward  # Setup all services (RECOMMENDED)"
	@echo "  make threats       # Open threat detection dashboard"
	@echo "  make status        # Check system status"
	@echo "  make logs          # View application logs"
	@echo "  make sync          # Force sync GitOps"

nodeport: ## Open NodePort services in browser
	@echo "🌐 Opening NodePort services..."
	@MINIKUBE_IP=$$(minikube ip -p ebpf-ia 2>/dev/null); \
	if [ "$$MINIKUBE_IP" != "" ]; then \
		echo "Opening Grafana Dashboard..."; \
		open "http://$$MINIKUBE_IP:30300" 2>/dev/null || xdg-open "http://$$MINIKUBE_IP:30300" 2>/dev/null || echo "Open manually: http://$$MINIKUBE_IP:30300"; \
		echo "Opening ArgoCD..."; \
		open "http://$$MINIKUBE_IP:31055" 2>/dev/null || xdg-open "http://$$MINIKUBE_IP:31055" 2>/dev/null || echo "Open manually: http://$$MINIKUBE_IP:31055"; \
	else \
		echo "❌ Minikube not running or IP not available"; \
	fi
lint-helm: ## Lint all Helm charts
	@echo "🧹 Linting Helm charts..."
	@helm lint helm/charts/ebpf-ai || true
	@helm lint helm/charts/prometheus || true
	@helm lint helm/charts/grafana || true
	@helm lint helm/charts/tekton-dashboard || true
	@helm lint helm/charts/registry || true

lint-code: ## Lint application code (Python + Go)
	@echo "🧹 Linting Python (ml-detector) with ruff + black --check"
	@command -v ruff >/dev/null 2>&1 && (cd applications/ml-detector && ruff .) || echo "ruff not installed"
	@command -v black >/dev/null 2>&1 && (cd applications/ml-detector && black --check .) || echo "black not installed"
	@echo "🧹 Linting Go (ebpf-monitor) with golangci-lint"
	@command -v golangci-lint >/dev/null 2>&1 && (cd applications/ebpf-monitor && golangci-lint run ./... || true) || echo "golangci-lint not installed"
