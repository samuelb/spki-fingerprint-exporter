{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "spki-fingerprint-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "spki-fingerprint-exporter.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "spki-fingerprint-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Selector labels. These must stay stable across releases because the
Deployment selector is immutable.
*/}}
{{- define "spki-fingerprint-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spki-fingerprint-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "spki-fingerprint-exporter.labels" -}}
{{ include "spki-fingerprint-exporter.selectorLabels" . }}
helm.sh/chart: {{ include "spki-fingerprint-exporter.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
{{- end -}}

{{/*
Name of the ServiceAccount to use.
*/}}
{{- define "spki-fingerprint-exporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "spki-fingerprint-exporter.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for ingress based on the cluster's
capabilities, falling back to the legacy APIs on old clusters.
*/}}
{{- define "spki-fingerprint-exporter.ingress.apiVersion" -}}
{{- if semverCompare ">=1.19-0" .Capabilities.KubeVersion.Version -}}
networking.k8s.io/v1
{{- else if semverCompare ">=1.14-0" .Capabilities.KubeVersion.Version -}}
networking.k8s.io/v1beta1
{{- else -}}
extensions/v1beta1
{{- end -}}
{{- end -}}

{{/*
Settings shared by every ServiceMonitor endpoint: how Prometheus reaches
the exporter when its listener is protected by a web config.
*/}}
{{- define "spki-fingerprint-exporter.serviceMonitor.endpointAccess" -}}
{{- with .Values.serviceMonitor.scheme }}
scheme: {{ . }}
{{- end }}
{{- with .Values.serviceMonitor.tlsConfig }}
tlsConfig:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.serviceMonitor.basicAuth }}
basicAuth:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
Label matchers that scope the built-in alerting rules to this exporter.
The chart's ServiceMonitor sets no jobLabel, so the job is the name of the
Service.
*/}}
{{- define "spki-fingerprint-exporter.ruleSelector" -}}
{{- if .Values.prometheusRule.selector -}}
{{- .Values.prometheusRule.selector -}}
{{- else -}}
{{- printf "job=%q, namespace=%q" (include "spki-fingerprint-exporter.fullname" .) .Release.Namespace -}}
{{- end -}}
{{- end -}}
