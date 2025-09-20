package pr.pathguard
import rego.v1

# Extract "app:<slug>" and "tenant:<slug>" labels from PR
allowed_app := app if {
  some l
  l := input.labels[_]
  startswith(l, "app:")
  app := split(l, ":")[1]
}
allowed_tenant := t if {
  some l
  l := input.labels[_]
  startswith(l, "tenant:")
  t := split(l, ":")[1]
}

# Build allowed prefixes
allowed_prefixes := {
  sprintf("apps/%s/", [allowed_app]),
  sprintf("tenants/dev/%s/", [allowed_tenant]),
}

# Friendly errors when labels are missing
deny contains "Missing label: add 'app:<app-slug>' (e.g., app:app-claims)" if { not allowed_app }
deny contains "Missing label: add 'tenant:<tenant-slug>' (e.g., tenant:claims-team)" if { not allowed_tenant }

# Deny any changed file outside allowed prefixes
deny contains msg if {
  f := input.files[_]
  not some p; p := allowed_prefixes[_]; startswith(f, p)
  msg := sprintf("Out-of-scope change: %s (allowed: %v)", [f, allowed_prefixes])
}
