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

# -------- team → app mapping (environment-level tenants only) --------
# Map app teams to their respective apps (both main team and reviewers team)
team_to_app := {
  "team-app1": "app1",
  "team-app1-reviewers": "app1",
  "team-app2": "app2",
  "team-app2-reviewers": "app2",
}

# Core bypass - ciam-core team can access everything
core_teams := {"ciam-core"}
core_bypass if { some t; actor_team_set[t]; core_teams[t] }

# -------- derive app from files --------
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

# -------- derive environment from files --------
envs_from_files := s if {
  valid_files
  s := {e | some f in input.files
    is_string(f)
    seg := split(norm_path(f), "/")
    count(seg) >= 2
    seg[0] == "tenants"
    e := lower(seg[1])
    e != ""
  }
} else := {} if { true }

derived_app := a if { count(apps_from_files) == 1; some x; apps_from_files[x]; a := x }
derived_env := e if { count(envs_from_files) == 1; some y; envs_from_files[y]; e := y }

# -------- effective values --------
effective_app := ea if { _ := derived_app; ea := derived_app }
effective_app := ea if { not derived_app; some ts in actor_team_set; ea := team_to_app[ts] }

effective_env := ee if { _ := derived_env; ee := derived_env }

has_effective_app if { _ := effective_app }
has_effective_env if { _ := effective_env }

# Get the actor's allowed app based on their team membership
actor_allowed_app := aa if {
  some ts in actor_team_set
  aa := team_to_app[ts]
}

has_actor_allowed_app if { _ := actor_allowed_app }

# -------- app authorization check --------
# Ensure actor team is authorized for the app they're touching
deny contains msg if {
  not core_bypass
  has_effective_app
  has_actor_allowed_app
  effective_app != actor_allowed_app
  msg := sprintf("Access denied: Your team (app: %s) cannot modify files in app: %s", [actor_allowed_app, effective_app])
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
  some f in input.files
  startswith(norm_path(f), "apps/")
  msg := "Cannot determine app (from paths or actor team)."
}

deny contains msg if {
  not core_bypass
  count(envs_from_files) > 1
  msg := sprintf("Multiple environments touched: %v. Limit PR to one environment.", [envs_from_files])
}

# -------- environment access control --------
# Non-core teams can only access dev environment
deny contains msg if {
  not core_bypass
  has_effective_env
  effective_env != "dev"
  msg := sprintf("Access denied: Only 'dev' environment is allowed. Attempted to access: %s", [effective_env])
}

# Prod access is completely blocked for non-core teams
deny contains msg if {
  not core_bypass
  valid_files
  some f in input.files
  startswith(norm_path(f), "tenants/prod/")
  msg := sprintf("Prod environment access is not allowed: %s", [f])
}

# -------- app scope enforcement --------
deny contains msg if {
  not core_bypass
  has_effective_app
  valid_files
  some f in input.files
  fp := norm_path(f)
  startswith(fp, "apps/")
  not startswith(fp, sprintf("apps/%s/", [effective_app]))
  msg := sprintf("App path out of scope: %s (expected apps/%s/)", [fp, effective_app])
}

# -------- allowed paths for app teams --------
# Define what app teams CAN access (whitelist approach)
allowed_paths_for_app_teams := {"apps/", "tenants/dev/", "tenants/qa/"}

# Check if a file path is allowed
path_is_allowed(fp) if {
  some allowed in allowed_paths_for_app_teams
  startswith(fp, allowed)
}

deny contains msg if {
  not core_bypass
  valid_files
  some f in input.files
  fp := norm_path(f)
  # Check if file does NOT start with any allowed path
  not path_is_allowed(fp)
  msg := sprintf("Access denied: %s (app teams can only access: apps/, tenants/dev/, tenants/qa/)", [f])
}