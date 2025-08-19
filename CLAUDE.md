# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Architecture Overview

This is an eBPF + AI GitOps platform implementing a complete infrastructure-as-code solution. The system combines eBPF network monitoring with AI-based threat detection, managed entirely through GitOps patterns.

### Core Components:
- **Ansible Bootstrap** - Day-0 infrastructure setup with Minikube, Cilium, ArgoCD
- **ArgoCD GitOps** - Declarative application management using App-of-Apps pattern  
- **Tekton CI/CD** - Automated image building and deployment pipelines
- **eBPF Applications** - ML Detector (Python) and eBPF Monitor (Go) for security monitoring

## Essential Commands

### Infrastructure Management
```bash
make bootstrap          # Complete infrastructure setup (15-20 min)
make status            # Health check across all components
make clean             # Teardown entire environment
make sync              # Force ArgoCD application synchronization
make port-forward      # Local access to services (ArgoCD:8080, Grafana:3000)
make test              # Basic functionality validation
```

### Development Workflow
```bash
# Deploy changes
git add . && git commit -m "description" && git push origin main
# ArgoCD auto-syncs within 3 minutes, or force with:
make sync

# Access services
kubectl port-forward svc/argocd-server -n argocd 8080:80
kubectl port-forward svc/kube-prometheus-stack-grafana -n monitoring 3000:80

# Check pipeline status
kubectl get pipelineruns,taskruns -n ebpf-security
kubectl get applications -n argocd
```

### Debugging Commands
```bash
# Check cluster status
kubectl get nodes
kubectl get pods -A
kubectl get applications -n argocd

# Pipeline debugging
kubectl describe pipelinerun <name> -n ebpf-security
kubectl logs <pod-name> -n ebpf-security

# ArgoCD debugging  
kubectl describe application ebpf-ai -n argocd
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller
```

## Configuration Architecture

### Environment Modes
The system supports two deployment modes via `ansible/group_vars/all.yml`:

**Lab Mode (default):**
```yaml
deployment_mode:
  type: "lab"
```
- NodePort services
- Podman driver  
- No MetalLB (simplified networking)
- Access via: `http://192.168.67.2:31055/argocd`

**Production Mode:**
```yaml
deployment_mode:
  type: "prod"  
```
- LoadBalancer services with MetalLB
- QEMU driver with bridge networking
- Real network IPs for direct access

### Key Configuration Files
- **`ansible/group_vars/all.yml`** - Environment settings, network config, resource limits
- **`helm/charts/ebpf-ai/values.yaml`** - Application configuration, image tags, ingress settings
- **`gitops/applications/`** - ArgoCD application definitions with sync policies

## Application Structure

### ML Detector (`applications/ml-detector/`)
Python Flask application providing AI-based threat detection:
- **Endpoints**: `/health`, `/metrics`, `/detect`
- **Dependencies**: Redis for caching, Prometheus for metrics
- **Configuration**: Via Helm values and environment variables

### eBPF Monitor (`applications/ebpf-monitor/`)  
Go application for eBPF-based network monitoring:
- **Endpoints**: `/health`, `/metrics`
- **Function**: Collects network metrics, integrates with ML Detector
- **Build**: Standard Go modules with CGO enabled for eBPF

## CI/CD Pipeline Architecture

### Pipeline Flow
1. **Git Push** → Tekton detects changes
2. **fetch-source** → Clone repository
3. **generate-tag** → Create semantic version tag
4. **build-image** → Buildah constructs container image
5. **sync-deploy** → Trigger ArgoCD sync

### Image Management
- **Registry**: Internal Minikube registry at `192.168.67.2:5000`
- **Tagging**: Semantic versioning with `v$major.$minor.$patch`
- **Storage**: Non-persistent for lab mode, configurable for production

## GitOps Patterns

### App-of-Apps Structure
```
ebpf-ai-apps (root)
├── ebpf-ai (main application)
├── tekton-pipelines (CI/CD platform)
├── tekton-ci-pipelines (pipeline definitions)
└── monitoring stack (Prometheus/Grafana)
```

### Sync Policies
- **Automated sync** with prune and self-heal
- **Retry logic** with exponential backoff
- **CreateNamespace** enabled for dynamic namespace creation

## Networking and Access

### Service Access Patterns
- **Ingress Routes**: `/argocd`, `/grafana`, `/dashboard` via NGINX
- **NodePort**: Direct service access in lab mode
- **LoadBalancer**: MetalLB managed IPs in production mode

### Default Credentials
- **ArgoCD**: admin/admin123
- **Grafana**: admin/admin123

## Development Notes

### Helm Chart Dependencies
The main `ebpf-ai` chart requires dependency builds:
```bash
cd helm/charts/ebpf-ai && helm dependency build
```

### ArgoCD Application Debugging
When applications show `OutOfSync` or `Degraded`:
1. Check application details: `kubectl describe application <name> -n argocd`
2. Look for template errors in Helm charts
3. Verify namespace existence and RBAC permissions
4. Force refresh: `kubectl patch application <name> -n argocd --type='merge' -p='{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}'`

### Tekton Pipeline Troubleshooting
For pipeline failures:
1. Check feature flags are enabled: `kubectl get configmap feature-flags -n tekton-pipelines`
2. Verify tasks exist in target namespace: `kubectl get tasks -n ebpf-security`
3. Check workspace permissions and PVC binding
4. Validate API versions match between pipelines and tasks (use `tekton.dev/v1`)

### Common Issues and Solutions
- **ImagePullBackOff**: Images need to be built via Tekton pipelines first
- **Permission errors in pipelines**: Ensure `fsGroup: 65532` in securityContext
- **ArgoCD OutOfSync**: Often due to Helm template validation errors - check logs
- **Registry connectivity**: Use internal IP `192.168.67.2:5000` for in-cluster access

The system prioritizes GitOps principles with everything managed declaratively through Git, automated CI/CD via Tekton, and comprehensive observability through Prometheus/Grafana stack.