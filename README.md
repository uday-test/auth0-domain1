# Auth0 DevOps Skeleton (Cigna) — Day 1

## Goal
Stand up a **clean repo scaffold** to support Auth0 configuration-as-code, policy checks, and CI/CD for Cigna domains.
This is the foundation for the multi-day plan (Days 1–14).

## Repository Layout
auth0-domain1/
│
├── base/
│   ├── base-line/
│   │   ├── configs/
│   │   │   ├── app-oidc.yml
│   │   │   ├── auth-settings.yml
│   │   │   ├── risk-settings.yml
│   │   │   └── ux-settings.yml
│   │   ├── policies/
│   │   │   └── baseline-validator.rego
│   │   └── validators/
│   │       ├── app-oidc-standard.yaml
│   │       ├── auth-settings-standard.yaml
│   │       ├── risk-settings-standard.yaml
│   │       └── ux-settings-standard.yaml
│   ├── policies/
│   │   ├── auth0_policy.rego
│   │   └── path_guard.rego
│   ├── tenants-common/
│   │   ├── orgs.yml
│   │   ├── security.yml
│   │   └── tokens.yml
│   └── terraform/
│       ├── main.tf
│       ├── terraform.tfstate.dev
│       └── variables.tf
│
├── overlays/
│   ├── policies/
│   │   └── shared_sec.rego
│   └── shared-sec/
│       └── identity_access.yml
│
├── tenants/
│   ├── dev/
│   │   ├── tenantA/
│   │   │   ├── app-oidc.yml
│   │   │   ├── auth-settings.yml
│   │   │   └── ux-settings.yml
│   │   └── tenantB/
│   │       ├── app-oidc.yml
│   │       ├── auth-settings.yml
│   │       └── ux-settings.yml
│   ├── qa/
│   │   ├── tenantA/
│   │   │   ├── app-oidc.yml
│   │   │   ├── auth-settings.yml
│   │   │   ├── risk-settings.yml
│   │   │   └── ux-settings.yml
│   │   └── tenantB/
│   │       ├── app-oidc.yml
│   │       ├── auth-settings.yml
│   │       ├── risk-settings.yml
│   │       └── ux-settings.yml
│   ├── prod/
│   │   ├── tenantA/
│   │   │   ├── app-oidc.yml
│   │   │   ├── auth-settings.yml
│   │   │   ├── risk-settings.yml
│   │   │   └── ux-settings.yml
│   │   └── tenantB/
│   │       ├── app-oidc.yml
│   │       ├── auth-settings.yml
│   │       ├── risk-settings.yml
│   │       └── ux-settings.yml
│   └── overlays/
│       ├── policies/
│       │   └── auth0_validation.rego
│       ├── validators/
│           ├── app-oidc-standard.yml
│           ├── auth-settings-standard.yml
│           ├── risk-settings-standard.yml
│           └── ux-settings-standard.yml
│       
│
├── apps/
│   ├── app1/
│   │   ├── orgs.yml
│   │   ├── security.yml
│   │   └── tokens.yml
│   └── app2/
│       ├── orgs.yml
│       ├── security.yml
│       └── tokens.yml
│
├── catalogs/
│
├── conftest-policy/
│
├── scripts/
│   
│
├── git/
├── CODEOWNERS
└── README.md

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
