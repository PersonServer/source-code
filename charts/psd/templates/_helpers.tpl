{{/* Chart name / fullname helpers.
     Adapted from apd (MIT OR Apache-2.0), github.com/AgentProvider/source-code. */}}
{{- define "psd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "psd.fullname" -}}
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

{{- define "psd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "psd.labels" -}}
helm.sh/chart: {{ include "psd.chart" . }}
{{ include "psd.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aauth
{{- end -}}

{{- define "psd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "psd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "psd.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "psd.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "psd.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Name of the Secret holding the signing keys (created or referenced). */}}
{{- define "psd.keysSecretName" -}}
{{- if .Values.keys.existingSecret -}}
{{- .Values.keys.existingSecret -}}
{{- else -}}
{{- printf "%s-keys" (include "psd.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Name of the PVC holding the SQLite database (created or referenced). */}}
{{- define "psd.dataClaimName" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-data" (include "psd.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Render psd.json from values + extraConfig. Only non-empty optional
     strings are emitted, so an unset value means "psd's default". */}}
{{- define "psd.configJson" -}}
{{- $c := .Values.config -}}
{{- $cfg := dict
  "issuer" .Values.issuer
  "listen" (printf "0.0.0.0:%d" (int .Values.service.port))
  "keys_file" "/etc/psd/keys/psd-keys.json"
  "storage" (dict "backend" "sqlite" "path" "/var/lib/psd/psd.db")
  "person_token_ttl_secs" $c.personTokenTtlSecs
  "auth_token_ttl_secs" $c.authTokenTtlSecs
  "signature_window_secs" $c.signatureWindowSecs
  "resource_token_max_age_secs" $c.resourceTokenMaxAgeSecs
  "retention_slack_secs" $c.retentionSlackSecs
  "missions" (dict "enabled" $c.missions.enabled "default_ttl_secs" $c.missions.defaultTtlSecs)
  "federation" (dict "enabled" $c.federation.enabled)
  "limits" (dict "resources_per_agent_per_day" $c.limits.resourcesPerAgentPerDay "code_attempts" $c.limits.codeAttempts "pending_ttl_secs" $c.limits.pendingTtlSecs)
  "ui" (dict "session_ttl_secs" $c.ui.sessionTtlSecs)
  "insecure_dev_mode" $c.insecureDevMode
-}}
{{- $notify := dict "channels" $c.notify.channels -}}
{{- if $c.notify.webhookUrl }}{{- $_ := set $notify "webhook_url" $c.notify.webhookUrl }}{{- end }}
{{- $_ := set $cfg "notify" $notify -}}
{{- $meta := dict -}}
{{- if $c.metadata.name }}{{- $_ := set $meta "name" $c.metadata.name }}{{- end }}
{{- if $c.metadata.description }}{{- $_ := set $meta "description" $c.metadata.description }}{{- end }}
{{- if $c.metadata.logoUri }}{{- $_ := set $meta "logo_uri" $c.metadata.logoUri }}{{- end }}
{{- if $c.metadata.documentationUri }}{{- $_ := set $meta "documentation_uri" $c.metadata.documentationUri }}{{- end }}
{{- if $c.metadata.tosUri }}{{- $_ := set $meta "tos_uri" $c.metadata.tosUri }}{{- end }}
{{- if $c.metadata.policyUri }}{{- $_ := set $meta "policy_uri" $c.metadata.policyUri }}{{- end }}
{{- $_ := set $cfg "metadata" $meta -}}
{{- if $c.expectedAuthority }}{{- $_ := set $cfg "expected_authority" $c.expectedAuthority }}{{- end }}
{{- if $c.auditLogFile }}{{- $_ := set $cfg "audit_log_file" $c.auditLogFile }}{{- end }}
{{- $merged := mergeOverwrite $cfg .Values.extraConfig -}}
{{- toPrettyJson $merged -}}
{{- end -}}
