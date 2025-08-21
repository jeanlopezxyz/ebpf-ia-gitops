# Manual PipelineRuns

This directory contains PipelineRun templates that are **NOT managed by ArgoCD GitOps**.

## Why separate from GitOps?

- PipelineRuns are execution instances, not infrastructure
- Using `generateName` conflicts with ArgoCD's `kubectl apply`
- Manual execution provides better control over CI/CD timing

## How to execute pipelines:

### Option 1: kubectl create
```bash
kubectl create -f manual-pipelineruns/pipelinerun-ebpf-ai-chart.yaml
kubectl create -f manual-pipelineruns/pipelinerun-ml-detector.yaml
```

### Option 2: Tekton Dashboard
1. Access Tekton Dashboard via `make port-forward`
2. Navigate to PipelineRuns
3. Create new PipelineRun from Pipeline

### Option 3: tkn CLI
```bash
tkn pipeline start helm-charts-ci
tkn pipeline start ml-detector-ci
tkn pipeline start ebpf-monitor-ci
```

## Available PipelineRuns:

- `pipelinerun-ebpf-ai-chart.yaml` - Updates eBPF-AI chart dependencies
- `pipelinerun-ml-detector.yaml` - Builds ML Detector image
- `pipelinerun-ebpf-monitor.yaml` - Builds eBPF Monitor image
- `pipelinerun-grafana-chart.yaml` - Updates Grafana chart
- `pipelinerun-prometheus-chart.yaml` - Updates Prometheus chart
- `pipelinerun-helm-charts.yaml` - General Helm charts CI

## Monitoring execution:

```bash
kubectl get pipelineruns -n tekton-pipelines
kubectl logs -f <pipelinerun-name> -n tekton-pipelines
```