# De GitOps a Helm: estandarizando eBPF + IA en Minikube con Argo CD y Tekton

Este artículo documenta, paso a paso, cómo convertimos manifiestos sueltos en charts Helm, unificamos convenciones (labels, namespaces, metadatos), añadimos linters y reforzamos la DX del repositorio. Todo sobre el stack eBPF + IA con Argo CD y Tekton, ejecutándose en Minikube.

## Contexto
- Repo: `ebpf-ia-gitops`
- Objetivo: convertir y estandarizar despliegues (Tekton Dashboard, ebpf-ai, tekton-ci, registry) y mejorar la mantenibilidad (linters, esquemas, Make targets).
- Orquestación: Argo CD (App-of-Apps), Tekton CI, Ingress NGINX, Cilium, Minikube.

## Resumen de cambios clave
- Tekton Dashboard pasado a Helm (`helm/charts/tekton-dashboard`) y enlazado en Argo CD.
- Chart `ebpf-ai` estandarizado: labels `app.kubernetes.io/*`, namespaces con `.Release.Namespace`, ServiceMonitor opcional, anotaciones de Prometheus condicionadas, ServiceAccounts parametrizables, `values.schema.json`, metadatos Chart unificados.
- Chart `tekton-ci` alineado (labels, namespaces explícitos en Tasks) y fix de `generate-tag`.
- Chart `registry` alineado (labels/selector DaemonSet CA + metadatos Chart).
- Aplicaciones Argo CD con labels uniformes (`component: argocd-app`).
- ML Detector: `.dockerignore`, manejo 400 para validación Pydantic, dev deps (pytest/black/ruff), pyproject.
- Makefile: targets `lint-helm` y `lint-code`, ajuste de port-forward para Grafana.

## Paso a paso

### 1) Tekton Dashboard a Helm + GitOps
- Se creó el chart `helm/charts/tekton-dashboard` con:
  - CRD `Extension` (en `crds/`), `ServiceAccount`, `RBAC`, `Service`, `Deployment`, `Ingress` opcional y `values.yaml` con flags.
- Se actualizó Argo CD: `gitops/applications/tekton-dashboard-app.yaml` ahora apunta al chart.
- Se eliminó el manifiesto crudo `gitops/tekton-dashboard/tekton-dashboard.yaml` para evitar duplicidad.

Comandos útiles:
```
helm template helm/charts/tekton-dashboard -n tekton-pipelines
```

### 2) Estandarización en `helm/charts/ebpf-ai`
- Labels y selectors: reemplazo de `app:`/`component:` por `app.kubernetes.io/*` en `Deployment`, `Service`, `Ingress`, `ServiceMonitor`, `HPA`, `PrometheusRule`, `ConfigMap`.
- Namespaces: todo usa `namespace: {{ .Release.Namespace }}`.
- ServiceMonitor: se volvió opcional (`serviceMonitor.enabled: false` por defecto).
- Anotaciones de Prometheus: ahora solo si `metrics.addPrometheusAnnotations: true` y `serviceMonitor.enabled: false` (para evitar doble scraping).
- ServiceAccounts:
  - `mlDetector.serviceAccount.create/name` + plantilla `templates/ml-detector-serviceaccount.yaml`.
  - `ebpfMonitor.serviceAccount.create/name` y binding actualizado en `ebpf-security-policy.yaml`.
- `values.schema.json`: validación básica de llaves y tipos.
- Chart.yaml: `icon`, `kubeVersion`, `home`, `sources`, `maintainers`, `annotations` de Artifact Hub.
- README del chart añadido.

Validación:
```
helm lint helm/charts/ebpf-ai
helm template helm/charts/ebpf-ai -n ebpf-security \
  --set serviceMonitor.enabled=true   # verás que no hay anotaciones prometheus.io/*
```

### 3) Tekton CI (`helm/charts/tekton-ci`)
- Labels estándar en `Task`, `Pipeline`, `PipelineRun`, `ServiceAccount`, `ClusterRole`, `ClusterRoleBinding`.
- Se añadió `namespace: {{ .Release.Namespace }}` en todas las `Task` para claridad.
- Fix: `pipeline-ml-detector.yaml` usa la task `generate-tag` (en vez de `generate-semantic-tag`).
- Chart.yaml normalizado e ícono de Tekton; README añadido.

### 4) Registry (`helm/charts/registry`)
- DaemonSet CA Installer con labels/selector estándar `app.kubernetes.io/*`.
- Chart.yaml con metadatos completos; README del chart añadido.

### 5) Argo CD Applications (`gitops/applications/*`)
- Labels uniformes: `app.kubernetes.io/name`, `app.kubernetes.io/part-of`, `app.kubernetes.io/component: argocd-app`.
- `app-of-apps.yaml` actualizado de igual forma.

### 6) Aplicación ML Detector
- `.dockerignore` para reducir contexto de build.
- Manejo de errores de validación (Pydantic) → 400 en `/detect`.
- `requirements-dev.txt`: `pytest`, `black`, `ruff`. `pyproject.toml` con config Black y Ruff.

### 7) Makefile y linters
- Nuevos targets:
```
make lint-helm   # helm lint en todos los charts
make lint-code   # ruff/black (ml-detector) y golangci-lint (ebpf-monitor)
```
- `make port-forward`: ajustado para `svc/grafana` según el chart actual.

## Validaciones realizadas
- `helm lint` OK en: ebpf-ai, tekton-ci, tekton-dashboard, registry.
- Renders de verificación (`helm template`) en charts clave para chequear labels/namespace/selectors.
- Make targets añadidos para acelerar QA local.

## Lecciones y decisiones
- Evitar duplicidad de scrape: cuando se usa Prometheus Operator, preferir `ServiceMonitor` y desactivar anotaciones `prometheus.io/*`.
- Usar `.Release.Namespace` y dejar que Argo CD gestione el namespace de destino.
- Estandarizar labels a `app.kubernetes.io/*` mejora seleccionadores y dashboards de observabilidad.
- Incluir `values.schema.json` reduce errores de tipado en `values.yaml`.

## Próximos pasos sugeridos
- Añadir CI que ejecute `make lint-helm` y `make lint-code` en PRs.
- Publicar charts en Artifact Hub (ya hay annotations de categoría).
- Documentar RBAC mínimo para `ebpf-monitor` y requisitos de privilegios (CAP_BPF, NET_ADMIN, etc.).
- Expandir pruebas de `ml-detector` (unit e2e con datos simulados) e integrar Tekton para pipelines de build.

## Cómo aplicar los cambios
- Sincronizar Argo CD:
```
make sync
```
- Revisar estado:
```
make status
kubectl get pods -A
```
- Acceso local rápido:
```
make port-forward
```

---
Última actualización: generada automáticamente como parte del trabajo de estandarización del repo.

