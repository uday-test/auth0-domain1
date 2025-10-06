# Auth0 DevOps Skeleton (Cigna) — Day 1

## Goal
Stand up a **clean repo scaffold** to support Auth0 configuration-as-code, policy checks, and CI/CD for Cigna domains.
This is the foundation for the multi-day plan (Days 1–14).

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
## Contribution Rules (Day 1)
- Use **feature branches** and open **PRs** into `main`.
- No direct pushes to `main`. (Formal branch protection enabled on Day 2.)
- Keep commits small and scoped.
- Do not commit **secrets** or PEM material. (Day 9 adds enforced scans.)

## PoC Scope (Phase 1)
- Scaffold repo and run a **sample CI smoke test**.
- Prepare for CODEOWNERS and path guards (Day 2).
- Prepare for OPA policies and conftest wiring (Days 3–4).
- Prepare tenant overlays and preview script (Day 5).

## GitHub Environments (create in repo Settings → Environments)
- `dev`, `qa`, `prod` for environment‑scoped secrets.
- Store future Auth0 deployer creds as: `DEV_AUTH0_CLIENT_ID`, `DEV_AUTH0_CLIENT_SECRET`, `DEV_AUTH0_DOMAIN`, etc. (Days 6–7).

## Running CI Locally (optional)
This repo currently ships a minimal smoke workflow. Day 4 will add `conftest` checks.
