package auth0.policy
import rego.v1

# Baseline guardrails for Auth0 application configs.
# Exposes two sets: deny (blocking) and warn (non-blocking).
#
# Expected input shape (examples in apps/**/resources/*.yaml):
# {
#   "metadata": {"name": "app1"},
#   "app": {
#     "type": "regular_web" | "spa",
#     "oauth": {
#        "grant_types": ["authorization_code", "refresh_token", ...],
#        "scopes": ["openid", "profile", "offline_access"]
#     }
#   },
#   "security": {
#     "mfa": { "factors": ["totp","webauthn"] }
#   },
#   "tokens": {
#     "id_token_ttl_seconds": 600,
#     "refresh_token": { "rotation_enabled": true }
#   }
# }
#
# Notes:
# - The policy is defensive about path shapes; it tolerates missing fields.
# - "warn" items do not block but will surface in Conftest output.

##########################
# Helpers & constants
##########################

# Small get() helper to safely read paths with a default
get(obj, keys, default) := out if {
  is_object(obj)
  out := walk_get(obj, keys, default)
}
walk_get(obj, keys, default) := v if {
  v := object.get(obj, keys[0], null)
  count(keys) == 1
  v != null
} else := walk_get(v, tail(keys), default) if {
  v := object.get(obj, keys[0], null)
  is_object(v)
  count(keys) > 1
} else := default if { true }

lower_or_empty(x) := y if { is_string(x); y := lower(x) } else := "" if { true }

# Safe array iteration: returns empty set if not array
arr(xs) := s if { is_array(xs); s := {x | some i; x := xs[i]} } else := {} if { true }

# Allow-list for app types
allowed_app_types := {"regular_web", "spa"}

# Canonicalize MFA factors presence from possible locations
mfa_factors := fs if {
  fs := union({
    {f | some x in arr(get(input, ["security","mfa","factors"], [])); is_string(x); f := lower(x)},
    {f | some x in arr(get(input, ["app","mfa","factors"], []));      is_string(x); f := lower(x)},
  })
}

# Canonicalize grant types & scopes
grant_types := {lower(x) | some x in arr(get(input, ["app","oauth","grant_types"], [])); is_string(x)}
scopes      := {lower(x) | some x in arr(get(input, ["app","oauth","scopes"], []));      is_string(x)}

app_name := lower_or_empty(get(input, ["metadata","name"], ""))
app_type := lower_or_empty(get(input, ["app","type"], ""))

# Token TTL (seconds) – accept either direct seconds or minutes (converted)
id_token_ttl_seconds := v if {
  v := get(input, ["tokens","id_token_ttl_seconds"], null)
  is_number(v)
} else := v if {
  m := get(input, ["tokens","id_token_ttl_minutes"], null)
  is_number(m)
  v := m * 60
}

# Refresh token rotation enabled?
rt_rotation_enabled := b if {
  v := get(input, ["tokens","refresh_token","rotation_enabled"], false)
  is_boolean(v)
  b := v
} else := false if { true }

##########################
# 1) App type allow-list
##########################
deny[msg] if {
  app_type != ""     # only enforce if set
  not allowed_app_types[app_type]
  msg := sprintf("app.type %q not allowed; allowed types: %v", [app_type, allowed_app_types])
}

##########################
# 2) Block password grant globally
##########################
password_aliases := {
  "password",
  "http://auth0.com/oauth/grant-type/password-realm"
}
deny[msg] if {
  some gt
  grant_types[gt]
  gt == "password" or gt == "http://auth0.com/oauth/grant-type/password-realm"
  msg := "password (resource owner) grant is blocked globally"
}

##########################
# 3) Block resource-owner on specific app (example)
##########################
deny[msg] if {
  app_name == "benefits-portal"
  some gt
  grant_types[gt]
  gt == "password" or gt == "http://auth0.com/oauth/grant-type/password-realm"
  msg := "benefits-portal: resource owner grant is explicitly blocked for this app"
}

##########################
# 4) Disallow baseline MFA factors (email, sms)
##########################
deny[msg] if {
  some f
  mfa_factors[f]
  f == "email" or f == "sms"
  msg := sprintf("MFA factor %q is disallowed by baseline (use TOTP/WebAuthn/push).", [f])
}

##########################
# 5) Token TTL: id_token < 10 minutes
##########################
deny[msg] if {
  is_number(id_token_ttl_seconds)
  id_token_ttl_seconds >= 600
  msg := sprintf("id_token TTL (%d s) must be < 600 s (10 minutes).", [id_token_ttl_seconds])
}

##########################
# 6) Warn if refresh_token mandate unmet
##########################
# Baseline: regular_web apps that use offline_access SHOULD have refresh token rotation enabled.
warn[msg] if {
  app_type == "regular_web"
  scopes["offline_access"]
  not rt_rotation_enabled
  msg := "refresh_token rotation SHOULD be enabled for regular_web apps using offline_access (warning)"
}

##########################
# 7) PEM armor scan anywhere in input
##########################
deny[msg] if {
  some p, v
  [p, v] := walk(input)
  is_string(v)
  re_match("-----BEGIN (CERTIFICATE|PRIVATE KEY)-----", v)
  msg := sprintf("PEM armor detected at path %v; never commit certs/keys.", [p])
}

