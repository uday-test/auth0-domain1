package pr.pathguard
import rego.v1

#
# Debug mode
# - Turn on by adding PR label:  debug:on
# - Or by setting input.debug = true (workflow can set this)
#
debug_enabled if { some l; l := input.labels[_]; l == "debug:on" }
debug_enabled if { input.debug == true }

# Helper to emit debug as WARN lines (non-blocking)
debug contains msg if {
  debug_enabled
  msg := sprintf("[debug] %s", [message])
} with message as input._debug_message  # used via 'with' at call sites (see bottom)

# ---- Label extraction ----

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

# ---- Allowed path prefixes ----

allowed_prefixes[p] if {
  app := allowed_app
  p := sprintf("apps/%s/", [app])
}

allowed_prefixes[p] if {
  t := allowed_tenant
  p := sprintf("tenants/dev/%s/", [t])
}

# Helper: file is within any allowed prefix
file_in_scope(f) if {
  some p
  p := allowed_prefixes[_]
  startswith(f, p)
}

# Deny any changed file outside allowed prefixes (only when both labels present)
deny contains msg if {
  allowed_app
  allowed_tenant
  f := input.files[_]
  not file_in_scope(f)
  msg := sprintf("Out-of-scope change: %s (allowed prefixes: %v)", [f, allowed_prefixes])
}

# ---- Debug WARNs (visible only if debug:on label or input.debug=true) ----

# Show raw labels and files
warn contains msg if {
  debug_enabled
  msg := sprintf("[debug] labels=%v", [input.labels])
}

warn contains msg if {
  debug_enabled
  msg := sprintf("[debug] files=%v", [input.files])
}

# Show derived values
warn contains msg if {
  debug_enabled
  msg := sprintf("[debug] allowed_app=%v allowed_tenant=%v", [allowed_app, allowed_tenant])
}

warn contains msg if {
  debug_enabled
  msg := sprintf("[debug] allowed_prefixes=%v", [allowed_prefixes])
}

# Per-file scope decision
warn contains msg if {
  debug_enabled
  f := input.files[_]
  msg := sprintf("[debug] file=%s in_scope=%v", [f, file_in_scope(f)])
}
