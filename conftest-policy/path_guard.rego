package pr.pathguard
import rego.v1

# ---------- helpers ----------
norm_path(p) := replace(p, "\\", "/")

debug_enabled if { input.debug == true }
debug_enabled if { some l in input.labels; l == "debug:on" }

valid_labels if { input.labels; is_array(input.labels) }
valid_files  if { input.files;  is_array(input.files)  }

# ---------- labels (optional) ----------
allowed_app := app if {
  valid_labels
  some lbl in input.labels
  is_string(lbl)
  startswith(lower(lbl), "app:")
  parts := split(lbl, ":")
  count(parts) >= 2
  app := lower(parts[1])
  app != ""
}

allowed_tenant := ten if {
  valid_labels
  some lbl in input.labels
  is_string(lbl)
  startswith(lower(lbl), "tenant:")
  parts := split(lbl, ":")
  count(parts) >= 2
  ten := lower(parts[1])
  ten != ""
}

# ---------- derive from files ----------
apps_from_files := s if {
  valid_files
  s := {a |
    some f in input.files
    is_string(f)
    fp := norm_path(f)
    seg := split(fp, "/")
    count(seg) >= 2
    seg[0] == "apps"
    a := lower(seg[1])
    a != ""
  }
}

tenants_from_files := s if {
  valid_files
  s := {t |
    some f in input.files
    is_string(f)
    fp := norm_path(f)
    seg := split(fp, "/")
    count(seg) >= 3
    seg[0] == "tenants"
    seg[1] == "dev"
    t := lower(seg[2])
    t != ""
  }
}

derived_app := a if {
  apps_from_files
  count(apps_from_files) == 1
  some a
  apps_from_files[a]
}

derived_tenant := t if {
  tenants_from_files
  count(tenants_from_files) == 1
  some t
  tenants_from_files[t]
}

# ---------- choose effective values (label wins; else derived) ----------
effective_app := a if { allowed_app; a := allowed_app } or { not allowed_app; derived_app; a := derived_app }
effective_tenant := t if { allowed_tenant; t := allowed_tenant } or { not allowed_tenant; derived_tenant; t := derived_tenant }

# ---------- conflicts & unknowns ----------
deny contains msg if {
  allowed_app
  derived_app
  allowed_app != derived_app
  msg := sprintf("Label app:%s does not match changed files (apps/%s/**).", [allowed_app, derived_app])
}

deny contains msg if {
  allowed_tenant
  derived_tenant
  allowed_tenant != derived_tenant
  msg := sprintf("Label tenant:%s does not match changed files (tenants/dev/%s/**).", [allowed_tenant, derived_tenant])
}

deny contains msg if {
  not effective_app
  apps_from_files
  count(apps_from_files) > 1
  msg := sprintf("Multiple apps touched: %v. Add 'app:<slug>' label or limit the PR to one app.", [apps_from_files])
}
deny contains msg if {
  not effective_app
  (not apps_from_files or count(apps_from_files) == 0)
  msg := "Cannot determine app from changes. Add label 'app:<slug>' or include files under apps/<slug>/"
}

deny contains msg if {
  not effective_tenant
  tenants_from_files
  count(tenants_from_files) > 1
  msg := sprintf("Multiple dev tenants touched: %v. Add 'tenant:<slug>' label or limit the PR to one tenant.", [tenants_from_files])
}
deny contains msg if {
  not effective_tenant
  (not tenants_from_files or count(tenants_from_files) == 0)
  msg := "Cannot determine tenant from changes. Add label 'tenant:<slug>' or include files under tenants/dev/<slug>/"
}

# ---------- prefixes & scope ----------
app_prefix := sprintf("apps/%s/", [effective_app]) if { effective_app }
tenant_prefix := sprintf("tenants/dev/%s/", [effective_tenant]) if { effective_tenant }

allowed_prefixes := prefixes if {
  aps := [app_prefix    | app_prefix]
  tps := [tenant_prefix | tenant_prefix]
  prefixes := array.concat(aps, tps)
}

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

# ---------- final deny ----------
deny contains msg if {
  effective_app
  effective_tenant
  valid_files
  some f in input.files
  is_string(f)
  f != ""
  not file_in_scope(f)
  msg := sprintf("Out-of-scope change: %s (allowed prefixes: %v)", [f, allowed_prefixes])
}

# ---------- debug (non-blocking) ----------
warn contains msg if { debug_enabled; msg := sprintf("[debug] labels=%v", [input.labels]) }
warn contains msg if { debug_enabled; msg := sprintf("[debug] files=%v",  [input.files])  }
warn contains msg if { debug_enabled; msg := sprintf("[debug] derived_app_set=%v",     [apps_from_files]) }
warn contains msg if { debug_enabled; msg := sprintf("[debug] derived_tenant_set=%v",  [tenants_from_files]) }
warn contains msg if { debug_enabled; effective_app;    msg := sprintf("[debug] effective_app=%v",    [effective_app]) }
warn contains msg if { debug_enabled; effective_tenant; msg := sprintf("[debug] effective_tenant=%v", [effective_tenant]) }
warn contains msg if { debug_enabled; allowed_prefixes; msg := sprintf("[debug] allowed_prefixes=%v", [allowed_prefixes]) }
warn contains msg if {
  debug_enabled
  valid_files
  some f in input.files
  is_string(f)
  ins := file_in_scope(f)
  msg := sprintf("[debug] file=%s in_scope=%v", [f, ins])
}
