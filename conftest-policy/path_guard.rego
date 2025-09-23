package pr.pathguard
import rego.v1

# -------- helpers --------
norm_path(p) := replace(p, "\\", "/")

debug_enabled if { input.debug == true }
valid_files if { input.files; is_array(input.files) }
valid_actor_teams if { input.actor_teams; is_array(input.actor_teams) }

# -------- actor teams --------
actor_team_set := s if {
  valid_actor_teams
  s := { lower(t) | some t in input.actor_teams; is_string(t) }
} else := {} if { true }

# -------- team → tenant → app mapping --------
team_to_tenant := {
  "team-app1": "app1-team",
  "team-app2": "app2-team",
}

tenant_to_app := {
  "app1-team": "app1",
  "app2-team": "app2",
}

# Optional: core bypass
core_teams := {"ciam-core"}
core_bypass if { some t; actor_team_set[t]; core_teams[t] }

# -------- derive from files --------
apps_from_files := s if {
  valid_files
  s := {a | some f in input.files
    is_string(f)
    seg := split(norm_path(f), "/")
    count(seg) >= 2
    seg[0] == "apps"
    a := lower(seg[1])
    a != ""
  }
} else := {} if { true }

tenants_from_files := s if {
  valid_files
  s := {t | some f in input.files
    is_string(f)
    seg := split(norm_path(f), "/")
    count(seg) >= 3
    seg[0] == "tenants"
    seg[1] == "dev"
    t := lower(seg[2])
    t != ""
  }
} else := {} if { true }

derived_app := a if { count(apps_from_files) == 1; some x; apps_from_files[x]; a := x }
derived_tenant := t if { count(tenants_from_files) == 1; some y; tenants_from_files[y]; t := y }

# -------- effective values (path > actor team) --------
effective_tenant := et if { _ := derived_tenant; et := derived_tenant }
effective_tenant := et if { not derived_tenant; some ts in actor_team_set; et := team_to_tenant[ts] }

effective_app := ea if { _ := derived_app; ea := derived_app }
effective_app := ea if { not derived_app; et := effective_tenant; ea := tenant_to_app[et] }

has_effective_app if { _ := effective_app }
has_effective_tenant if { _ := effective_tenant }

# -------- enforce tenant→app pairing --------
deny contains msg if {
  not core_bypass
  has_effective_tenant
  not tenant_to_app[effective_tenant]
  msg := sprintf("Tenant %q has no registered app mapping; configure tenant_to_app.", [effective_tenant])
}

deny contains msg if {
  not core_bypass
  has_effective_tenant
  has_effective_app
  expected_app := tenant_to_app[effective_tenant]
  expected_app != effective_app
  msg := sprintf("Team/app mismatch: tenant %q is paired with app %q, but PR touches app %q.", [effective_tenant, expected_app, effective_app])
}

# -------- ambiguity checks --------
deny contains msg if {
  not core_bypass
  not has_effective_app
  count(apps_from_files) > 1
  msg := sprintf("Multiple apps touched: %v. Limit PR to one app.", [apps_from_files])
}
deny contains msg if {
  not core_bypass
  not has_effective_app
  count(apps_from_files) == 0
  msg := "Cannot determine app (from paths or actor team)."
}

deny contains msg if {
  not core_bypass
  not has_effective_tenant
  count(tenants_from_files) > 1
  msg := sprintf("Multiple dev tenants touched: %v. Limit PR to one tenant.", [tenants_from_files])
}
deny contains msg if {
  not core_bypass
  not has_effective_tenant
  count(tenants_from_files) == 0
  msg := "Cannot determine tenant (from paths or actor team)."
}

# -------- prefixes & scope helpers --------
app_prefix := ap if { has_effective_app; ap := sprintf("apps/%s/", [effective_app]) }
tenant_prefix := tp if { has_effective_tenant; tp := sprintf("tenants/dev/%s/", [effective_tenant]) }

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
  some p; prefix_set[p]
  startswith(fp, p)
}

# -------- denies --------
deny contains msg if {
  not core_bypass
  valid_files
  some f in input.files
  fp := norm_path(f)
  startswith(fp, "apps/")
  not startswith(fp, sprintf("apps/%s/", [effective_app]))
  msg := sprintf("App path out of scope: %s (expected apps/%s/)", [fp, effective_app])
}
deny contains msg if {
  not core_bypass
  valid_files
  some f in input.files
  fp := norm_path(f)
  startswith(fp, "tenants/dev/")
  not startswith(fp, sprintf("tenants/dev/%s/", [effective_tenant]))
  msg := sprintf("Tenant path out of scope: %s (expected tenants/dev/%s/)", [fp, effective_tenant])
}
deny contains msg if {
  not core_bypass
  valid_files
  some f in input.files
  startswith(norm_path(f), "tenants/prod/")
  msg := sprintf("Prod tenant path is not allowed: %s", [f])
}

deny contains msg if {
  not core_bypass
  valid_files
  some f in input.files
  not startswith(norm_path(f), "apps/")
  not startswith(norm_path(f), "tenants/dev/")
  not startswith(norm_path(f), "tenants/qa/")
  not startswith(norm_path(f), "tenants/prod/")
  not startswith(norm_path(f), "base/")
  not startswith(norm_path(f), "overlays/")
  not startswith(norm_path(f), "conftest-policy/")
  msg := sprintf("Out-of-scope change: %s (allowed prefixes: %v)", [f, allowed_prefixes])
}
