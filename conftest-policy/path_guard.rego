package pr.pathguard
import rego.v1

# -------- helpers --------
norm_path(p) := replace(p, "\\", "/")

debug_enabled if { input.debug == true }
debug_enabled if { input.labels; is_array(input.labels); some l in input.labels; l == "debug:on" }

valid_labels if { input.labels; is_array(input.labels) }
valid_files  if { input.files;  is_array(input.files)  }

deny contains "Invalid input: 'labels' must be an array" if { input.labels; not is_array(input.labels) }
deny contains "Invalid input: 'files' must be an array"  if { input.files;  not is_array(input.files)  }

# -------- labels (optional) --------
allowed_app := app if {
  valid_labels
  some lbl in input.labels
  is_string(lbl)
  parts := split(lbl, ":")
  count(parts) >= 2
  startswith(lower(lbl), "app:")
  app := lower(parts[1])
  app != ""
}

allowed_tenant := ten if {
  valid_labels
  some lbl in input.labels
  is_string(lbl)
  parts := split(lbl, ":")
  count(parts) >= 2
  startswith(lower(lbl), "tenant:")
  ten := lower(parts[1])
  ten != ""
}

# -------- derive from files (always-defined sets) --------
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
} else := {} if { true }

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
} else := {} if { true }

derived_app := a if {
  count(apps_from_files) == 1
  some x
  apps_from_files[x]
  a := x
}

derived_tenant := t if {
  count(tenants_from_files) == 1
  some y
  tenants_from_files[y]
  t := y
}

# existence helpers (no var rebind)
has_allowed_app    if { _ := allowed_app }
has_allowed_tenant if { _ := allowed_tenant }
has_derived_app    if { _ := derived_app }
has_derived_tenant if { _ := derived_tenant }

# -------- effective values --------
effective_app := ea if {
  has_allowed_app
  ea := allowed_app
}
effective_app := ea if {
  not has_allowed_app
  has_derived_app
  ea := derived_app
}

effective_tenant := et if {
  has_allowed_tenant
  et := allowed_tenant
}
effective_tenant := et if {
  not has_allowed_tenant
  has_derived_tenant
  et := derived_tenant
}

has_effective_app    if { _ := effective_app }
has_effective_tenant if { _ := effective_tenant }

# -------- conflicts / unknowns --------
deny contains msg if {
  has_allowed_app
  has_derived_app
  la := allowed_app
  da := derived_app
  la != da
  msg := sprintf("Label app:%s does not match changed files (apps/%s/**).", [la, da])
}

deny contains msg if {
  has_allowed_tenant
  has_derived_tenant
  lt := allowed_tenant
  dt := derived_tenant
  lt != dt
  msg := sprintf("Label tenant:%s does not match changed files (tenants/dev/%s/**).", [lt, dt])
}

deny contains msg if {
  not has_effective_app
  count(apps_from_files) > 1
  msg := sprintf("Multiple apps touched: %v. Add 'app:<slug>' label or limit the PR to one app.", [apps_from_files])
}
deny contains msg if {
  not has_effective_app
  count(apps_from_files) == 0
  msg := "Cannot determine app from changes. Add label 'app:<slug>' or include files under apps/<slug>/"
}

deny contains msg if {
  not has_effective_tenant
  count(tenants_from_files) > 1
  msg := sprintf("Multiple dev tenants touched: %v. Add 'tenant:<slug>' label or limit the PR to one tenant.", [tenants_from_files])
}
deny contains msg if {
  not has_effective_tenant
  count(tenants_from_files) == 0
  msg := "Cannot determine tenant from changes. Add label 'tenant:<slug>' or include files under tenants/dev/<slug>/"
}

# -------- prefixes & scope helpers --------
app_prefix := ap if {
  has_effective_app
  ea := effective_app
  ap := sprintf("apps/%s/", [ea])
}
tenant_prefix := tp if {
  has_effective_tenant
  et := effective_tenant
  tp := sprintf("tenants/dev/%s/", [et])
}

prefix_set := s if {
  s1 := {p | p := app_prefix}
  s2 := {p | p := tenant_prefix}
  s := union({s1, s2})
}

allowed_prefixes := arr if {
  aps := [p | p := app_prefix]
  tps := [p | p := tenant_prefix]
  arr := array.concat(aps, tps)
}

file_in_scope(f) if {
  is_string(f)
  fp := norm_path(f)
  ps := prefix_set
  some p
  ps[p]
  startswith(fp, p)
}

# -------- early denies (strict) --------
deny contains msg if {
  has_effective_app
  valid_files
  some f in input.files
  is_string(f)
  fp := norm_path(f)
  startswith(fp, "apps/")
  not startswith(fp, sprintf("apps/%s/", [effective_app]))
  msg := sprintf("App path out of scope: %s (expected under apps/%s/)", [fp, effective_app])
}

deny contains msg if {
  has_effective_tenant
  valid_files
  some f in input.files
  is_string(f)
  fp := norm_path(f)
  startswith(fp, "tenants/dev/")
  not startswith(fp, sprintf("tenants/dev/%s/", [effective_tenant]))
  msg := sprintf("Dev-tenant path out of scope: %s (expected under tenants/dev/%s/)", [fp, effective_tenant])
}

deny contains msg if {
  valid_files
  some f in input.files
  is_string(f)
  startswith(norm_path(f), "tenants/prod/")
  msg := sprintf("Prod tenant path is not allowed in app-team PRs: %s", [f])
}

# -------- final out-of-scope guard --------
deny contains msg if {
  has_effective_app
  has_effective_tenant
  valid_files
  some f in input.files
  is_string(f)
  f != ""
  not file_in_scope(f)
  msg := sprintf("Out-of-scope change: %s (allowed prefixes: %v)", [f, allowed_prefixes])
}

# -------- debug (non-blocking) --------
warn contains msg if { debug_enabled; msg := sprintf("[debug] labels=%v", [input.labels]) }
warn contains msg if { debug_enabled; msg := sprintf("[debug] files=%v",  [input.files])  }
warn contains msg if { debug_enabled; msg := sprintf("[debug] derived_app_set=%v",    [apps_from_files]) }
warn contains msg if { debug_enabled; msg := sprintf("[debug] derived_tenant_set=%v", [tenants_from_files]) }
warn contains msg if { debug_enabled; has_effective_app;    msg := sprintf("[debug] effective_app=%v",    [effective_app]) }
warn contains msg if { debug_enabled; has_effective_tenant; msg := sprintf("[debug] effective_tenant=%v", [effective_tenant]) }
warn contains msg if { debug_enabled; allowed_prefixes;     msg := sprintf("[debug] allowed_prefixes=%v", [allowed_prefixes]) }
warn contains msg if {
  debug_enabled
  valid_files
  some f in input.files
  is_string(f)
  ins := file_in_scope(f)
  msg := sprintf("[debug] file=%s in_scope=%v", [f, ins])
}
