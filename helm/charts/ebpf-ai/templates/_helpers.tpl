{{/*
Expand the name of the chart.
*/}}
{{- define "ebpf-ai.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ebpf-ai.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ebpf-ai.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ebpf-ai.labels" -}}
helm.sh/chart: {{ include "ebpf-ai.chart" . }}
{{ include "ebpf-ai.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ebpf-ai.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ebpf-ai.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use for ML Detector
*/}}
{{- define "ebpf-ai.mlDetector.serviceAccountName" -}}
{{- if .Values.mlDetector.serviceAccount.create }}
{{- default (printf "%s-ml-detector" (include "ebpf-ai.fullname" .)) .Values.mlDetector.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.mlDetector.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for eBPF Monitor
*/}}
{{- define "ebpf-ai.ebpfMonitor.serviceAccountName" -}}
{{- if .Values.ebpfMonitor.serviceAccount.create }}
{{- default (printf "%s-ebpf-monitor" (include "ebpf-ai.fullname" .)) .Values.ebpfMonitor.serviceAccount.name }}
{{- else }}
{{- default "ebpf-monitor" .Values.ebpfMonitor.serviceAccount.name }}
{{- end }}
{{- end }}