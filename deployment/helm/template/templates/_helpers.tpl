{{/*
Common labels
*/}}
{{- define "template-plugin.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{ include "template-plugin.selectorLabels" . }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "template-plugin.selectorLabels" -}}
app.kubernetes.io/name: nri-resource-policy-template
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
