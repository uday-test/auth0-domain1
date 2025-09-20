package pr.pathguard
import rego.v1

#
# Debug mode:
#   - Add PR label:  debug:on
#   - Or set input.debug = true (workflow builds input.json)
#
debug_enabled if { some l; l := input.labels[_]; l == "debug:on" }
debug_enabled if { input.debug == true }

# ---- Label extraction ----
# Expect labels:  app:<slug>   and   tenant:<slug>

allowed_app := app if {
  some l
  l := input.labels[_]
  startswith(l, "app:")
  parts := split(l, ":")
  count(parts) == 2
  app := parts[1]
}

allowed_tenant := t if {
  some l
  l := input.labels[_]
  startswith(l, "tenant:")
  parts := split(l, ":")
  count(parts) == 2
  t := parts[1]
}

# Friendly errors if required labels are missing
deny contains "Missing label: add 'app:<app-slug>' (e.g., app:app-claims)" if { not allowed_app }
deny contains "Missing label: add 'tenant:<tenant-slug>' (e.g., tenant:claims-team)" if { not allowed_tenant }

# ---- Allowed path prefixes derived from labels ----
allowed_prefixes[p] if {
  app := allowed_app
  p := sprintf("apps/%s/", [app])
}
allowed_prefixes[p] if {
  t := allowed_tenant
  p := sprintf("tenants/dev/%s/", [t])
}

# Helper: does a file live under any allowed prefix?
file_in_scope(f) if {
  some p
  p := allowed_prefixes[_]
  startswith(f, p)
}

# Deny any changed file outside allowed prefixes
# (only after both labels are present)
deny contains msg if {
  allowed_app
  allowed_tenant
  f := input.files[_]
  not file_in_scope(f)
  msg := sprintf("Out-of-scope change: %s (allowed prefixes: %v)", [f, {p | p := allowed_prefixes[_]}])
}

# ---- Debug WARNs (non-blocking; shown only when debug is enabled) ----

# Show raw labels/files
warn contains msg if {
  debug_enabled
  msg := sprintf("[debug] labels=%v", [input.labels])
}
warn contains msg if {
  debug_enabled
  msg := sprintf("[debug] files=%v", [input.files])
}

# Show derived values when available
warn contains msg if {
  debug_enabled
  allowed_app
  msg := sprintf("[debug] allowed_app=%v", [allowed_app])
}
warn contains msg if {
  debug_enabled
  allowed_tenant
  msg := sprintf("[debug] allowed_tenant=%v", [allowed_tenant])
}
warn contains msg if {
  debug_enabled
  msg := sprintf("[debug] allowed_prefixes=%v", [{p | p := allowed_prefixes[_]}])
}

# Per-file scope decision
warn contains msg if {
  debug_enabled
  f := input.files[_]
  msg := sprintf("[debug] file=%s in_scope=%v", [f, file_in_scope(f)])
}
