# 🚀 eBPF + AI GitOps Project

## Modern Deployment with Ansible + Helm + ArgoCD

This project implements a complete GitOps workflow for the eBPF + AI monitoring system using:

- **Ansible**: Infrastructure bootstrap and configuration
- **Helm**: Application packaging and templating
- **ArgoCD**: GitOps continuous deployment
- **Minikube**: Local Kubernetes cluster

## 📁 Project Structure

```
ebpf-ia-gitops/
├── ansible/
│   ├── bootstrap.yml              # Main bootstrap playbook
│   ├── inventory/
│   │   └── localhost.yml
│   ├── roles/
│   │   ├── minikube/
│   │   ├── metallb/
│   │   ├── cilium/
│   │   └── argocd/
│   └── group_vars/
│       └── all.yml
├── helm/
│   ├── charts/
│   │   ├── infrastructure/        # MetalLB, Cilium, etc.
│   │   └── ebpf-ai/              # Main application chart
│   └── helmfile.yaml
├── gitops/
│   ├── applications/             # ArgoCD Application manifests
│   └── app-of-apps.yaml         # ArgoCD App-of-Apps pattern
├── src/                         # Application source code (from original project)
└── docs/
    └── deployment.md
```

## 🚀 Quick Start

### Prerequisites
- Docker
- Ansible
- kubectl
- helm

### 1. Bootstrap Infrastructure
```bash
# Clone and enter directory
git clone <this-repo>
cd ebpf-ia-gitops

# Bootstrap complete stack
ansible-playbook ansible/bootstrap.yml

# Wait for ArgoCD to be ready (2-3 minutes)
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=argocd-server -n argocd --timeout=300s
```

### 2. Access Services
```bash
# Get ArgoCD admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Port forward ArgoCD UI
kubectl port-forward svc/argocd-server -n argocd 8080:443

# Access: https://localhost:8080 (admin / <password-from-above>)
```

### 3. Deploy Applications via GitOps
```bash
# Applications are automatically deployed by ArgoCD
# Monitor deployment status
argocd app list
argocd app get ebpf-ai
```

## 🔄 Development Workflow

1. **Modify application**: Edit files in `helm/charts/ebpf-ai/`
2. **Commit changes**: `git add . && git commit -m "Update ML detector"`
3. **Push to repository**: `git push origin main`
4. **ArgoCD syncs automatically** (or manually trigger in UI)

## 📊 Monitoring & Access

- **ArgoCD UI**: `https://localhost:8080`
- **Grafana**: `http://localhost:3000` (admin/admin)
- **Prometheus**: `http://localhost:9090`
- **ML Detector API**: `http://localhost:5500`

## 🛠️ Management Commands

```bash
# Sync specific application
argocd app sync ebpf-ai

# Rollback to previous version
argocd app rollback ebpf-ai

# Delete everything
ansible-playbook ansible/cleanup.yml
```

## 📚 Documentation

- [Deployment Guide](docs/deployment.md)
- [Development Workflow](docs/development.md)
- [Troubleshooting](docs/troubleshooting.md)