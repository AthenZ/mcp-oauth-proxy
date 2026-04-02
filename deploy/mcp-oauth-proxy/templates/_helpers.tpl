{{/*
Expand the name of the chart.
*/}}
{{- define "mcp-oauth-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "mcp-oauth-proxy.fullname" -}}
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
{{- define "mcp-oauth-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mcp-oauth-proxy.serviceVersion" -}}
{{- printf "%s:%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Return the raw namespace (forceNamespace or release namespace), matching b2b-auth0-api chart.
*/}}
{{- define "mcp-oauth-proxy.rawnamespace" -}}
{{- if .Values.forceNamespace -}}
{{ print .Values.forceNamespace }}
{{- else -}}
{{ print .Release.Namespace }}
{{- end -}}
{{- end -}}

{{/*
Namespace line for Instrumentation metadata (indent under metadata:).
*/}}
{{- define "mcp-oauth-proxy.namespace" -}}
{{ printf "namespace: %s" (include "mcp-oauth-proxy.rawnamespace" .) }}
{{- end }}

{{/*
TLS cert path for OTEL exporter mTLS (Athenz SIA layout, same as b2b-auth0-api).
*/}}
{{- define "mcp-oauth-proxy.tlsCert" -}}
{{- printf "/var/lib/sia/certs/%s.%s.cert.pem" .Values.athenz.domain .Values.athenz.service -}}
{{- end -}}

{{/*
TLS key path for OTEL exporter mTLS (Athenz SIA layout, same as b2b-auth0-api).
*/}}
{{- define "mcp-oauth-proxy.tlsKey" -}}
{{- printf "/var/lib/sia/keys/%s.%s.key.pem" .Values.athenz.domain .Values.athenz.service -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "mcp-oauth-proxy.labels" -}}
helm.sh/chart: {{ include "mcp-oauth-proxy.chart" . }}
{{ include "mcp-oauth-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "mcp-oauth-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-oauth-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "mcp-oauth-proxy.serviceAccountName" -}}
{{- default "default" (printf "%s.%s" .Values.athenz.domain .Values.athenz.service) }}
{{- end }}
