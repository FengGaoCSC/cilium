{{/*
Enterprise-only cilium-config entries
*/}}
{{- define "enterprise.cilium-config" }}
# SRv6 Locator Pool support
srv6-locator-pool-enabled:  {{ .Values.enterprise.srv6.locatorPoolEnabled | default .Values.enterprise.srv6.locatorPoolEnabled | default "false" | quote }}

{{- if .Values.enterprise.multiNetwork.enabled }}
# Multi-network support
enable-multi-network: {{ .Values.enterprise.multiNetwork.enabled | quote }}
{{- if hasKey .Values.enterprise.multiNetwork "autoCreateDefaultPodNetwork" }}
auto-create-default-pod-network: {{ .Values.enterprise.multiNetwork.autoCreateDefaultPodNetwork | quote }}
{{- end }}
{{- if hasKey .Values.enterprise.multiNetwork "autoDirectNodeRoutes" }}
multi-network-auto-direct-node-routes: {{ .Values.enterprise.multiNetwork.autoDirectNodeRoutes | quote }}
{{- end }}
{{- end }}

{{- end }}