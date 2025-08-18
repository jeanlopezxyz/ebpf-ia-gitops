# Repository Guidelines

## Project Structure & Module Organization
- `ansible/`: Bootstrap, cleanup, and roles (minikube, cilium, metallb, argocd, ingress, storage). Inventory in `ansible/inventory/` and vars in `ansible/group_vars/all.yml`.
- `helm/charts/ebpf-ai/`: Main chart (Deployments/Services/HPA/Ingress, values in `values.yaml`).
- `gitops/`: Argo CD App-of-Apps in `app-of-apps.yaml` and application specs in `gitops/applications/`.
- `applications/`: App sources and Dockerfiles (`ml-detector` Python, `ebpf-monitor` Go).
- `tekton/`: CI pipelines and tasks (build, tag, Argo CD sync).
- `docs/`, `dashboards/`: Ops docs and Grafana dashboards.

## Build, Test, and Development Commands
- `make help`: List available commands.
- `make check-deps`: Verify Docker, kubectl, helm, ansible, minikube.
- `make bootstrap`: Create local cluster and install Argo CD + stack.
- `make status` / `make logs`: Inspect cluster/apps status and tail key logs.
- `make port-forward`: Local access to Argo CD, Grafana, Prometheus, services.
- `make sync` / `make deploy`: Sync Argo CD apps; force with `--force`.
- `make test`: Basic health check for `ml-detector` via port-forward + curl.
- `make clean` or `make restart`: Tear down or rebuild environment.

## Coding Style & Naming Conventions
- YAML/Helm: 2-space indent; lower-kebab-case resource names; standard labels (`app.kubernetes.io/*`). Run `helm lint helm/charts/ebpf-ai` before PRs.
- Kubernetes: Default namespace `ebpf-security`; avoid hardcoding cluster IPs; template via values.
- Python (`applications/ml-detector`): Prefer Black formatting and type hints; keep Flask endpoints small.
- Go (`applications/ebpf-monitor`): `gofmt`, `go vet`; module path rooted at `applications/ebpf-monitor`.
- Branches: `feature/<area>-<short>`, `fix/<area>-<short>`, `chore/<task>`.

## Testing Guidelines
- Fast checks: `make test`, `make status`, and `kubectl get pods -n ebpf-security`.
- Service health: `kubectl port-forward svc/ml-detector -n ebpf-security 5000:5000` then `curl :5000/health`.
- Helm render: `helm template helm/charts/ebpf-ai -f helm/charts/ebpf-ai/values.yaml`.
- Tekton: Apply kustomize in `tekton/` and use provided PipelineRuns for app builds.

## Commit & Pull Request Guidelines
- Commits: Imperative, concise subject (≤72 chars). Optional scope prefix: `tekton:`, `helm:`, `ansible:`, `gitops:`, `apps:`. Example: `helm: add HPA for ml-detector`.
- PRs: Describe motivation + changes, link issues, include relevant outputs (e.g., `make status`), and screenshots for dashboards. Ensure `helm lint` passes and `make test` is green.

## Security & Configuration Tips
- Do not commit secrets. Use Kubernetes Secrets and values overrides.
- Centralize env in `ansible/group_vars/all.yml` (e.g., `deployment_mode.type: lab|prod`, registry, ingress hosts).
- Run containers as non-root (already enforced in Dockerfiles/Tekton); keep it.
