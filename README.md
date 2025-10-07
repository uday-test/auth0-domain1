# Auth0 DevOps Skeleton (Cigna)



## Repository Layout
```
auth0-domain1/
│
├── base/
│   ├── base-line/
│   │   ├── configs/ (4 YAML files: app-oidc, auth-settings, risk-settings, ux-settings)
│   │   ├── policies/
│   │   │   └── baseline-validator.rego (Validates configurations against baseline standards)
│   │   └── validators/ (4 YAML files: standards for app-oidc, auth-settings, risk-settings, ux-settings)
│   ├── policies/
│   │   ├── auth0_policy.rego (validates configuration on all apps in the root level)
│   │   └── path_guard.rego (Enforces path-based access control and ownership)
│   ├── tenants-common/ (3 YAML files: standards for orgs, security, tokens )
│   └── terraform/ (3 files: main.tf, terraform.tfstate.dev, variables.tf)
│
├── overlays/
│   ├── policies/
│   │   └── shared_sec.rego (Security overlay validation and enforcement across the levels)
│   └── shared-sec/ (1 YAML file:standard file identity_access)
│
├── tenants/
│   ├── dev/
│   │   ├── tenantA/ (3 YAML files: app-oidc, auth-settings, ux-settings)
│   │   └── tenantB/ (3 YAML files: app-oidc, auth-settings, ux-settings)
│   ├── qa/
│   │   ├── tenantA/ (4 YAML files: app-oidc, auth-settings, risk-settings, ux-settings)
│   │   └── tenantB/ (4 YAML files: app-oidc, auth-settings, risk-settings, ux-settings)
│   ├── prod/
│   │   ├── tenantA/ (4 YAML files: app-oidc, auth-settings, risk-settings, ux-settings)
│   │   └── tenantB/ (4 YAML files: app-oidc, auth-settings, risk-settings, ux-settings)
│   └── overlays/
│       ├── policies/
│       │   └── auth0_validation.rego (Tenant-specific validation rules)
│       ├── validators/ (4 YAML files: standards for app-oidc, auth-settings, risk-settings, ux-settings)
│       
│
├── apps/
│   ├── app1/ (3 YAML files: orgs, security, tokens)
│   └── app2/ (3 YAML files: orgs, security, tokens)
│
├── catalogs/ 
├── scripts/
├── git/
├── CODEOWNERS
└── README.md
```

