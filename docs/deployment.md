# 🚀 Deployment Guide

## Overview

This guide covers the complete deployment process for the eBPF + AI GitOps system using Ansible, Helm, and ArgoCD.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GitOps Workflow                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Developer → Git Push → ArgoCD → Helm → Kubernetes         │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                Infrastructure Components                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Minikube → Cilium → MetalLB → ArgoCD → Applications        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Required Tools
```bash
# macOS
brew install ansible kubectl helm docker minikube

# Ubuntu/Debian
sudo apt update
sudo apt install ansible kubectl
curl https://get.helm.sh/helm-v3.13.0-linux-amd64.tar.gz | tar xz
sudo mv linux-amd64/helm /usr/local/bin/

# Install minikube
curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube /usr/local/bin/
```

### System Requirements
- **CPU**: 4+ cores
- **Memory**: 8GB+ RAM
- **Disk**: 20GB+ free space
- **Docker**: Running and accessible

## Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/ebpf-ia-gitops.git
cd ebpf-ia-gitops
```

### 2. Configure Variables
Edit `ansible/group_vars/all.yml`:
```yaml
applications:
  ebpf_ai:
    git_repo: "https://github.com/yourusername/ebpf-ia-gitops.git"  # Your repo URL
```

### 3. Bootstrap Infrastructure
```bash
# Install Ansible collections
ansible-galaxy collection install kubernetes.core

# Run bootstrap
ansible-playbook -i ansible/inventory/localhost.yml ansible/bootstrap.yml
```

### 4. Verify Deployment
```bash
# Check cluster status
kubectl get nodes

# Check ArgoCD
kubectl get pods -n argocd

# Check applications
kubectl get apps -n argocd
```

## Detailed Steps

### Step 1: Infrastructure Bootstrap

The bootstrap process installs:

1. **Minikube Cluster** (3 nodes, 8GB RAM, 4 CPUs)
2. **Cilium CNI** with eBPF features
3. **MetalLB** LoadBalancer
4. **ArgoCD** GitOps controller

```bash
ansible-playbook -i ansible/inventory/localhost.yml ansible/bootstrap.yml -v
```

### Step 2: ArgoCD Configuration

ArgoCD is configured with:
- **App-of-Apps** pattern for managing multiple applications
- **Automated sync** with prune and self-heal
- **Helm integration** for templating

### Step 3: Application Deployment

Applications are deployed via GitOps:
```bash
# Monitor ArgoCD applications
argocd app list

# Force sync if needed
argocd app sync ebpf-ai
```

## Access Information

### ArgoCD UI
```bash
# Get LoadBalancer IP
kubectl get svc argocd-server -n argocd

# Or port forward
kubectl port-forward svc/argocd-server -n argocd 8080:80

# Access: http://localhost:8080
# Username: admin
# Password: admin123
```

### Grafana Dashboard
```bash
# Get LoadBalancer IP
kubectl get svc ebpf-ai-grafana -n ebpf-security

# Or port forward
kubectl port-forward svc/ebpf-ai-grafana -n ebpf-security 3000:80

# Access: http://localhost:3000
# Username: admin
# Password: admin
```

### ML Detector API
```bash
# Port forward
kubectl port-forward svc/ml-detector -n ebpf-security 5000:5000

# Test API
curl http://localhost:5000/health
```

## Troubleshooting

### Common Issues

#### Minikube Won't Start
```bash
# Check Docker
docker ps

# Restart minikube
minikube delete --profile ebpf-gitops
minikube start --profile ebpf-gitops --memory=8192 --cpus=4
```

#### ArgoCD Applications Not Syncing
```bash
# Check ArgoCD logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller

# Manual sync
argocd app sync ebpf-ai --force
```

#### Pods Stuck in Pending
```bash
# Check node resources
kubectl describe nodes

# Check events
kubectl get events -n ebpf-security --sort-by='.lastTimestamp'
```

#### MetalLB LoadBalancer Pending
```bash
# Check MetalLB logs
kubectl logs -n metallb-system -l app=metallb

# Verify IP pool
kubectl get ipaddresspool -n metallb-system
```

### Resource Monitoring
```bash
# Check resource usage
kubectl top nodes
kubectl top pods -n ebpf-security

# Monitor cluster events
kubectl get events --all-namespaces --sort-by='.lastTimestamp'
```

## Cleanup

### Complete Cleanup
```bash
ansible-playbook -i ansible/inventory/localhost.yml ansible/cleanup.yml
```

### Partial Cleanup
```bash
# Delete only applications
argocd app delete ebpf-ai

# Delete only cluster
minikube delete --profile ebpf-gitops
```

## Production Considerations

### Security
- Change default ArgoCD password
- Enable RBAC
- Use private Git repositories
- Enable network policies

### Scalability
- Increase resource limits
- Enable horizontal pod autoscaling
- Use persistent storage for production

### Monitoring
- Configure alerts
- Set up log aggregation
- Monitor GitOps sync status

## Next Steps

1. [Development Workflow](development.md)
2. [Monitoring Guide](monitoring.md)
3. [Customization](customization.md)