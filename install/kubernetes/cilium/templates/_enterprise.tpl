{{/*
Enterprise-only cilium-config entries
*/}}
{{- define "enterprise.cilium-config" }}
# SRv6 Locator Pool support
srv6-locator-pool-enabled:  {{ .Values.enterprise.srv6.locatorPoolEnabled | default .Values.enterprise.srv6.locatorPoolEnabled | default "false" | quote }}
{{- end }}
