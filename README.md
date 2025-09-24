# Auth0 DevOps Skeleton (Cigna) — Day 1

## Goal
Stand up a **clean repo scaffold** to support Auth0 configuration-as-code, policy checks, and CI/CD for Cigna domains.
This is the foundation for the multi-day plan (Days 1–14).

## Repository Layout
```text
base/                 # Baseline policies and shared building blocks (no tenant-specific secrets)
  policies/           # Will hold OPA/Rego policies (Day 3)
  tenants-common/     # Org-wide Auth0 config, prompts, MFA baseline (Day 5)
overlays/             # Hardening overlays layered on top of base
  shared-sec/         # Security overlays (TTL, factor restrictions) (Day 5)
tenants/              # Per-environment tenant config
  dev/
  qa/
  prod/
apps/                 # App-specific resources (each app in its own folder) (Day 10)
catalogs/             # Optionally shared catalogs (connections, grants, customs)
scripts/              # Helper scripts (preview.sh, deploy.sh to be added in Day 5+7)
.github/workflows/    # CI workflows
CODEOWNERS            # Will be populated in Day 2
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
"# Workflow optimized: $(date)" 
"# Workflow is safely optimized: $(date)" 
"# Workflow is safely optimized: $(date)" 
