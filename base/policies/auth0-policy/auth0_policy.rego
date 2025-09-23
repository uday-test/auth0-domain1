package auth0.policy
import rego.v1

# === DENY rules (blocking) ===

# Allow-list for app type (regular_web, spa)
deny contains msg if {
  is_string(input.app_type)
  t := lower(input.app_type)
  not {"regular_web","spa"}[t]
  msg := sprintf("app.type %q not allowed; allowed: regular_web, spa", [t])
}

# Block password grant globally (incl. realm alias)
deny contains msg if {
  is_array(input.grant_types)
  some i
  is_string(input.grant_types[i])
  gt := lower(input.grant_types[i])
  {"password","http://auth0.com/oauth/grant-type/password-realm"}[gt]
  msg := "password (resource owner) grant is blocked globally"
}

# Special case: benefits-portal + password grant → explicit deny
deny contains msg if {
  is_string(input.name)
  lower(input.name) == "benefits-portal"
  is_array(input.grant_types)
  some i
  is_string(input.grant_types[i])
  gt := lower(input.grant_types[i])
  {"password","http://auth0.com/oauth/grant-type/password-realm"}[gt]
  msg := "benefits-portal: resource owner grant is explicitly blocked for this app"
}

# MFA bans: email, sms
deny contains msg if {
  is_array(input.mfa_factors)
  some i
  is_string(input.mfa_factors[i])
  f := lower(input.mfa_factors[i])
  {"email","sms"}[f]
  msg := sprintf("MFA factor %q is disallowed by baseline (use TOTP/WebAuthn/push).", [f])
}

# Token TTL limit (< 600s)
deny contains msg if {
  is_number(input.id_token_lifetime)
  input.id_token_lifetime >= 600
  msg := sprintf("id_token TTL (%d s) must be < 600 s (10 minutes).", [input.id_token_lifetime])
}

# PEM armor scan anywhere in the document
deny contains msg if {
  some i
  pair := walk(input)[i]                    # [path, value]
  is_string(pair[1])
  regex.match("-----BEGIN (CERTIFICATE|PRIVATE KEY)-----", pair[1])
  msg := sprintf("PEM armor detected at path %v; never commit certs/keys.", [pair[0]])
}

# === helper: refresh rotation enabled? ===
refresh_rotation_enabled if {
  v := input.refresh_token_rotation_enabled
  v == true
}

# === WARN rules (non-blocking) ===

# Warn if regular_web + offline_access but refresh rotation is off (or missing)
warn contains msg if {
  is_string(input.app_type)
  lower(input.app_type) == "regular_web"
  is_array(input.scopes)
  some i
  is_string(input.scopes[i])
  lower(input.scopes[i]) == "offline_access"
  not refresh_rotation_enabled
  msg := "refresh_token rotation SHOULD be enabled for regular_web apps using offline_access (warning)"
}
