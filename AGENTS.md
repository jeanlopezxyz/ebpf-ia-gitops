# Repository Guidelines

This guide helps you build, test, and operate the eBPF AI stack managed via Ansible, Helm, Tekton, and Argo CD.

## Project Structure & Module Organization
- `ansible/`: Cluster bootstrap/cleanup and roles (minikube, cilium, metallb, argocd, ingress, storage). Inventory in `ansible/inventory/`; globals in `ansible/group_vars/all.yml`.
- `helm/charts/ebpf-ai/`: Main app chart (Deployments/Services/HPA/Ingress). Grafana dashboards under `grafana/*.json` loaded by sidecar.
- `gitops/`: Argo CD App-of-Apps in `app-of-apps.yaml`; application specs in `gitops/applications/`.
- `applications/`: App sources + Dockerfiles — `ml-detector` (Python), `ebpf-monitor` (Go).
- `helm/charts/tekton-ci/`: Tekton Tasks/Pipelines/ PipelineRuns packaged as Helm.
- `docs/`, `dashboards/`: Ops docs and Grafana dashboards.

## Build, Test, and Development Commands
- `make help`: List available targets.
- `make check-deps`: Validate Docker, kubectl, helm, ansible, minikube.
- `make bootstrap`: Create local cluster and install Argo CD + stack.
- `make status` / `make logs`: Inspect app status; tail key logs.
- `make port-forward`: Local access to Argo CD, Grafana, Prometheus, services.
- `make sync` / `make deploy`: Sync Argo CD apps; force with `--force`.
- `make test`: Health check for `ml-detector` via port-forward + curl.
- `make clean` or `make restart`: Tear down or rebuild.

## Coding Style & Naming Conventions
- YAML/Helm: 2-space indent; lower-kebab-case names; standard labels `app.kubernetes.io/*`. Run `helm lint helm/charts/ebpf-ai`.
- Kubernetes: Default namespace `ebpf-security`; avoid hardcoded IPs; template via values.
- Python (`applications/ml-detector`): Black formatting, type hints; keep Flask endpoints small.
- Go (`applications/ebpf-monitor`): `gofmt`, `go vet`; module path rooted at `applications/ebpf-monitor`.

## Testing Guidelines
- Fast checks: `make test`, `make status`, `kubectl get pods -n ebpf-security`.
- Service health: `kubectl port-forward svc/ml-detector -n ebpf-security 5000:5000` then `curl :5000/health`.
- Helm render: `helm template helm/charts/ebpf-ai -f helm/charts/ebpf-ai/values.yaml`.
- Tekton: Deployed via `helm/charts/tekton-ci` and managed by Argo CD app `tekton-ci-pipelines`.

## Commit & Pull Request Guidelines
- Commits: Imperative, concise subject (≤72 chars). Optional scope prefix: `tekton:`, `helm:`, `ansible:`, `gitops:`, `apps:` (e.g., `helm: add HPA for ml-detector`).
- PRs: Explain motivation and changes, link issues, include outputs (e.g., `make status`) and dashboard screenshots. Ensure `helm lint` passes and `make test` is green.

## Security & Configuration Tips
- Never commit secrets; use Kubernetes Secrets and values overrides.
- Centralize env in `ansible/group_vars/all.yml` (e.g., `deployment_mode.type: lab|prod`, registry, ingress hosts).
- Containers run as non-root by default; keep it. Defaults like `registry.enabled: false` and `prom_stack.enabled: false` are managed later via Argo CD.

