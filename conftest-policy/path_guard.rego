package pr.pathguard
import rego.v1

# -------------- helpers --------------
# Normalize backslashes on Windows
norm_path(p) := replace(p, "\\", "/")

# Case-insensitive startswith (optional)
starts_with_ci(s, prefix) := startswith(lower(s), lower(prefix))

# Debug toggle
debug_enabled if { input.debug == true }
debug_enabled if { some lbl in input.labels; lbl == "debug:on" }

# Input shape checks (non-blocking; used by denies below)
valid_labels if { input.labels; is_array(input.labels) }
valid_files  if { input.files;  is_array(input.files)  }

# -------------- label extraction --------------
# Expect labels like: app:app-claims, tenant:claims-team
allowed_app := app if {
  valid_labels
  some lbl_app in input.labels
  is_string(lbl_app)
  starts_with_ci(lbl_app, "app:")
  parts := split(lbl_app, ":")
  count(parts) >= 2
  app := lower(parts[1])
  app != ""
}

allowed_tenant := ten if {
  valid_labels
  some lbl_ten in input.labels
  is_string(lbl_ten)
  starts_with_ci(lbl_ten, "tenant:")
  parts := split(lbl_ten, ":")
  count(parts) >= 2
  ten := lower(parts[1])
  ten != ""
}

# -------------- friendly errors --------------
deny contains "Invalid input: 'labels' must be an array" if { input.labels; not is_array(input.labels) }
deny contains "Invalid input: 'files' must be an array"  if { input.files;  not is_array(input.files)  }

deny contains "Missing label: add 'app:<app-slug>' (e.g., app:app-claims)" if { valid_labels; not allowed_app }
deny contains "Missing label: add 'tenant:<tenant-slug>' (e.g., tenant:claims-team)" if { valid_labels; not allowed_tenant }

# -------------- allowed prefixes --------------
app_prefix := sprintf("apps/%s/", [allowed_app]) if { allowed_app }
tenant_prefix := sprintf("tenants/dev/%s/", [allowed_tenant]) if { allowed_tenant }

# Gather prefixes for messages/debug
allowed_prefixes := prefixes if {
  aps := [app_prefix   | app_prefix]
  tps := [tenant_prefix| tenant_prefix]
  prefixes := array.concat(aps, tps)
}

# -------------- scope check --------------
file_in_scope(f) if {
  is_string(f)
  ap := app_prefix
  startswith(norm_path(f), ap)
}
file_in_scope(f) if {
  is_string(f)
  tp := tenant_prefix
  startswith(norm_path(f), tp)
}

# -------------- deny out-of-scope --------------
deny contains msg if {
  allowed_app
  allowed_tenant
  valid_files
  some f in input.files
  is_string(f)
  f != ""
  not file_in_scope(f)
  msg := sprintf("Out-of-scope change: %s (allowed prefixes: %v)", [f, allowed_prefixes])
}

# -------------- debug WARNs (non-blocking) --------------
warn contains msg if { debug_enabled; msg := sprintf("[debug] labels=%v", [input.labels]) }
warn contains msg if { debug_enabled; msg := sprintf("[debug] files=%v",  [input.files])  }
warn contains msg if { debug_enabled; allowed_app;    msg := sprintf("[debug] allowed_app=%v",    [allowed_app]) }
warn contains msg if { debug_enabled; allowed_tenant; msg := sprintf("[debug] allowed_tenant=%v", [allowed_tenant]) }
warn contains msg if { debug_enabled; allowed_prefixes; msg := sprintf("[debug] allowed_prefixes=%v", [allowed_prefixes]) }
warn contains msg if {
  debug_enabled
  valid_files
  some f in input.files
  is_string(f)
  in_scope := file_in_scope(f)
  msg := sprintf("[debug] file=%s in_scope=%v", [f, in_scope])
}
