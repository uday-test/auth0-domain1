# Auth0-Domain1 – Repository & Policy-Driven CI/CD Documentation

## Table of Contents
1. [Overview & Objectives](#1-overview--objectives)
2. [Repository Architecture & Folder Layout](#2-repository-architecture--folder-layout)
3. [Access Control & Path Governance](#3-access-control--path-governance)
   - [3.1 CODEOWNERS Review Model](#31-codeowners-review-model)
   - [3.2 PR Path Guard Policy](#32-pr-path-guard-policy)
4. [Standards Framework & Policy Enforcement](#4-standards-framework--policy-enforcement)
   - [4.1 Baseline Standards vs Baseline Configurations](#41-baseline-standards-vs-baseline-configurations)
   - [4.2 Environment-Specific Tenant Standards (Overlays)](#42-environment-specific-tenant-standards-overlays)
   - [4.3 Application-Level Standards & Validations](#43-application-level-standards--validations)
   - [4.4 Enterprise Shared Security Overlay](#44-enterprise-shared-security-overlay)
5. [Continuous Integration & Delivery Pipelines (CI/CD)](#5-continuous-integration--delivery-pipelines-cicd)
   - [5.1 PR Validation Workflow – `.github/workflows/pr-checks.yml`](#51-pr-validation-workflow--githubworkflowspr-checksyml)
   - [5.2 Terraform Plan Validation – `.github/workflows/terraform-check.yml`](#52-terraform-plan-validation--githubworkflowsterraform-checkyml)
   - [5.3 Deployment Workflow – `.github/workflows/terraform-deploy.yml`](#53-deployment-workflow--githubworkflowsterraform-deployyml)
   - [5.4 Secret Verification – `.github/workflows/ci-smoke.yml`](#54-secret-verification--githubworkflowsci-smokeyml)
6. [Terraform Deployment Model](#6-terraform-deployment-model)
7. [Configuration Data Flow](#7-configuration-data-flow)
8. [Enforcement Scenarios & Real-World Examples](#8-enforcement-scenarios--real-world-examples)
9. [Extensibility & Future Enhancements](#9-extensibility--future-enhancements)
10. [Policy Input Schema Reference](#10-policy-input-schema-reference)
11. [Operational Guidance & Governance Notes](#11-operational-guidance--governance-notes)
    - [11.1 Policy & Workflow File References](#111-policy--workflow-file-references)
12. [Initial Setup & Environment Prerequisites](#12-initial-setup--environment-prerequisites)
    1. [Create GitHub Teams (RBAC Model)](#121-create-github-teams-rbac-model)
    2. [Configure GitHub Environments & Secrets](#122-configure-github-environments--secrets)
    3. [Provision Auth0 M2M Clients (Per Environment)](#123-provision-auth0-m2m-clients-per-environment)
    4. [Set Organization Token (Fine-Grained PAT)](#124-set-organization-token-fine-grained-pat)
    5. [Enforce Naming & Path Conventions](#125-enforce-naming--path-conventions)
    6. [Grant GitHub Action Permissions](#126-grant-github-action-permissions)
    7. [Tooling Baseline & Version Matrix](#127-tooling-baseline--version-matrix)
    8. [Validation Checklist (Pre-Deployment)](#128-validation-checklist-pre-deployment)

---

## 1) Overview & Objectives

This repository codifies **Auth0 tenant and application configuration**, along with **security and compliance standards**, entirely as code.  
It integrates **policy-as-code**, **CI/CD automation**, and **Terraform-based infrastructure management** to ensure every configuration change is reviewable, validated, and reproducible.

It uses:

- **[OPA/Rego policies](#4-standards-framework--policy-enforcement)** with **Conftest** to validate YAML configuration files against defined standards before deployment.  
- **[GitHub Actions workflows](#5-continuous-integration--delivery-pipelines-cicd)** to enforce [path ownership and RBAC](#3-access-control--path-governance), validate [baseline configurations](#41-baseline-standards-vs-baseline-configurations), [tenant overlays](#42-environment-specific-tenant-standards-overlays), and [application-level settings](#43-application-level-standards--validations), while automating Terraform checks and deployments.  
- **[Terraform automation](#6-terraform-deployment-model)** to apply validated and approved baseline configurations directly to Auth0 tenants using environment-specific M2M credentials.

> Primary CI/CD jobs reside in [`.github/workflows/`](#5-continuous-integration--delivery-pipelines-cicd), and policies live under  
> [`base/**`](#41-baseline-standards-vs-baseline-configurations), [`tenants/**`](#42-environment-specific-tenant-standards-overlays), and [`overlays/**`](#44-enterprise-shared-security-overlay).

---

## 2) Repository Architecture & Folder Layout

```
auth0-domain1/
├─ .github/workflows/
│  ├─ ci-smoke.yml                  # Secret smoke test for Auth0 deployer creds
│  ├─ pr-checks.yml                 # Main PR policy-gating pipeline (Conftest)
│  ├─ terraform-check.yml           # Terraform plan/guard after PR checks pass
│  └─ terraform-deploy.yml          # On push to main – deploy baseline via TF
│
├─ CODEOWNERS                       # Team-based ownership and review rules
├─ README.md                        # Repo documentation
│
├─ apps/
│  ├─ app1/
│  │  ├─ orgs.yml                   # Org behaviors
│  │  ├─ security.yml               # App security & OAuth settings
│  │  └─ tokens.yml                 # Token/JWT/refresh token settings
│  └─ app2/ ...                     # Same structure as app1
│
├─ base/
│  ├─ base-line/
│  │  ├─ configs/                   # Golden baseline configs (4 YAMLs)
│  │  │  ├─ app-oidc.yml
│  │  │  ├─ auth-settings.yml
│  │  │  ├─ risk-settings.yml
│  │  │  └─ ux-settings.yml
│  │  ├─ policies/
│  │  │  └─ baseline-validator.rego # Validates merged baseline config vs standards
│  │  └─ validators/                # Baseline standards (4 YAMLs)
│  │     ├─ app-oidc-standard.yaml
│  │     ├─ auth-settings-standard.yaml
│  │     ├─ risk-settings-standard.yaml
│  │     └─ ux-settings-standard.yaml
│  ├─ policies/
│  │  ├─ path_guard.rego            # PR path guard (apps/ & env rules)
│  │  └─ auth0_policy.rego          # App config validator (tokens/security/orgs)
│  ├─ tenants-common/               # App security standards consumed by policies
│  │  ├─ orgs.yml
│  │  ├─ security.yml
│  │  └─ tokens.yml
│  └─ terraform/
│     ├─ main.tf                    # Auth0 provider resources from baseline config
│     └─ variables.tf               # Auth0 domain & M2M secrets
│
├─ overlays/
│  ├─ policies/
│  │  └─ shared_sec.rego            # Enterprise shared security hardening checks
│  └─ shared-sec/
│     └─ identity_access.yml        # Enterprise password/MFA requirements
│
├─ tenants/
│  ├─ dev/
│  │  ├─ tenantA/ (app-oidc.yml, auth-settings.yml, ux-settings.yml)
│  │  └─ tenantB/ (...)
│  ├─ qa/
│  │  ├─ tenantA/ (app-oidc.yml, auth-settings.yml, risk-settings.yml, ux-settings.yml)
│  │  └─ tenantB/ (...)
│  ├─ prod/
│  │  ├─ tenantA/ (app-oidc.yml, auth-settings.yml, risk-settings.yml, ux-settings.yml)
│  │  └─ tenantB/ (...)
│  └─ overlays/
│     ├─ policies/
│     │  └─ auth0_validation.rego   # Env-aware validation (dev/qa/prod)
│     └─ validators/                # Env-specific standards (OIDC/auth/risk/UX)
│        ├─ app-oidc-standard.yml
│        ├─ auth-settings-standard.yml
│        ├─ risk-settings-standard.yml
│        └─ ux-settings-standard.yml
│
├─ catalogs/                        # (reserved)
├─ scripts/                         # (reserved)
└─ git                              # (reserved)
```

---

## 3) Access Control & Path Governance

### 3.1 CODEOWNERS Review Model
- File: `CODEOWNERS`
- Default owner: `@uday-test/ciam-core` for everything.
- App folders: `/apps/app1/` → `@uday-test/team-app1-reviewers`, `/apps/app2/` → `@uday-test/team-app2-reviewers`.
- CI workflows, base configs, policies, catalogs, scripts, and CODEOWNERS itself → `@uday-test/ciam-core`.

This ensures the right reviewers must approve changes in app- or platform-owned paths before merging.

### 3.2 PR Path Guard Policy
- File: `base/policies/path_guard.rego`
- Inputs: (provided by the workflow) changed `files[]`, actor `actor_teams[]`, and optional `env`.
- Behavior:
  - Maps teams ↔ apps (`team-app1`, `team-app2`, including `*-reviewers`).
  - **Core bypass:** `ciam-core` can touch anything.
  - **App scoping:** Non-core teams may only change their own app under `apps/<app>/...`.
  - **Environment scoping:** Non-core teams are limited to `tenants/dev/...`; touching `tenants/prod/...` is always denied.

**Why it matters:** Improper cross-app changes or unauthorized env changes are blocked **before** any policy or Terraform runs.

---

## 4) Standards Framework & Policy Enforcement

### 4.1 Baseline Standards vs Baseline Configurations
- **Standards (authoritative expectations):**
  - `base/base-line/validators/*.yaml` (4 files) define required schema/values for:
    - `app-oidc`, `auth-settings`, `risk-settings`, and `ux-settings`.
- **Configs (intended baseline values):**
  - `base/base-line/configs/*.yml` provide actual baseline values.
- **Policy:** `base/base-line/policies/baseline-validator.rego`
  - Conftest merges all baseline config files and all standard files into a single input document:
    ```yaml
    config:   # merged from base-line/configs/*.yml
    standard: # merged from base-line/validators/*.yaml
    ```
  - The policy checks **required fields exist**, **must_equal**, **min/max**, etc., at multiple nesting levels.

> Outcome: If a baseline config drifts from standard, PR fails in “Baseline Config Validation.”

### 4.2 Environment-Specific Tenant Standards (Overlays)
- **Standards:** `tenants/overlays/validators/*.yml` encode **dev/qa/prod** specific rules (e.g., grant types, PKCE, HTTPS, UX restrictions, risk controls).
- **Policy:** `tenants/overlays/policies/auth0_validation.rego`
  - Detects `env` from inputs (issuer patterns, allowed origins, branding URL hints) and applies the correct env’s rules.
  - Examples enforced:
    - `require_https`: dev can be relaxed, qa/prod must be true.
    - `enforce_pkce`: required in qa/prod, relaxed in dev depending on client type.
    - Allowed `grant_types` by env; implicit is allowed only in dev (if configured).

> Outcome: Edits under `tenants/<env>/<tenantX>/*.yml` are validated against **that env’s** standards.

### 4.3 Application-Level Standards & Validations
- **Standards (common, enterprise):** `base/tenants-common/*.yml`
  - `security.yml` (e.g., allowed grant types and response types per `spa`, `regular_web`, `native`, CORS rules, OIDC conformance, token endpoint auth methods, cross-origin auth expectations, etc.)
  - `tokens.yml` (JWT alg/lifetimes, refresh token rotation/absolute lifetime, etc.)
  - `orgs.yml` (organization usage rules and behaviors)
- **Configs (per app):** `apps/<app>/{security.yml,tokens.yml,orgs.yml}`
- **Policy:** `base/policies/auth0_policy.rego`
  - Inputs: `input.security`, `input.tokens`, `input.orgs`, plus derived `input.app_type` (e.g., SPA, regular_web, native) inferred by the workflow from the folder name.
  - Validates app configs against common standards, e.g.:
    - **Grant types**: SPA → `authorization_code`, forbid implicit in enterprise prod context; Regular Web → `authorization_code` and proper client auth; Native → no client secret.
    - **Response types** and **CORS/web origins** alignment with client type.
    - **JWT/refresh token** lifetimes and rotation.
    - **Org behaviors** alignment (`allow`, prompt behavior).

> Outcome: PRs that touch `apps/<app>/*` are auto-validated against enterprise standards.

### 4.4 Enterprise Shared Security Overlay
- **Standards:** `overlays/shared-sec/identity_access.yml` (e.g., min password length, history, and MFA factors to be enabled/disabled enterprise-wide)
- **Policy:** `overlays/policies/shared_sec.rego`
  - Merges/normalizes required factors and checks identity access settings meet or exceed enterprise requirements.

> Outcome: A single place to harden shared/enterprise-wide auth posture beyond app or tenant specifics.

---

## 5) Continuous Integration & Delivery Pipelines (CI/CD)

### 5.1 PR Validation Workflow – `.github/workflows/pr-checks.yml`
**Triggers:** `pull_request` to `main` (opened, reopened, synchronize, edited, ready_for_review) and manual `workflow_dispatch`.

**Jobs (in order):**

1) **setup**
   - Installs/caches **Conftest** and **yq** binaries for later jobs.

2) **path-guard** (needs: setup)
   - Computes changed files (`git diff` base..head).
   - Collects actor’s teams and constructs **Conftest input** with `files[]` + `actor_teams[]`.
   - Runs `base/policies/path_guard.rego` to **block**:
     - Cross-app edits (e.g., team-app1 trying to touch `apps/app2/*`).
     - Any edits touching `tenants/prod/*` by non-core teams.
     - Edits outside `tenants/dev/*` for non-core teams.

3) **baseline-config-validation** (needs: setup, path-guard)
   - Detects if baseline files under `base/base-line/{configs,validators}` changed in the PR; if not, it **skips**.
   - If changed, merges the four **configs** and four **standards** via `yq` into a **single input YAML** and runs Conftest against `base/base-line/policies/baseline-validator.rego`.

4) **tenant-config-validation** (needs: setup, path-guard)
   - Detects whether PR touches any `tenants/<env>/tenant*/{app-oidc,auth-settings,risk-settings,ux-settings}.yml`.
   - For each environment found (`dev`, `qa`, `prod`), merges tenant files and validates with `tenants/overlays/policies/auth0_validation.rego` against the env-aware standards in `tenants/overlays/validators/*`.

5) **app-config-validation** (needs: setup, path-guard)
   - Detects whether PR touches `apps/*/(tokens|security|orgs).yml`.
   - Iterates each `apps/<app>/` directory, infers **app_type** (`spa`, `regular_web`, `native`), and validates the three app files with `base/policies/auth0_policy.rego` against `base/tenants-common/*` standards.

> **Fail-fast behavior:** Any denial from Rego causes the job to fail and the PR check to turn red.

### 5.2 Terraform Plan Validation – `.github/workflows/terraform-check.yml`
**Trigger:** `pull_request` to `main` when paths under `base/base-line/configs/**` change.

**Behavior:**
- Waits for the PR checks above (Path Guard + Baseline Validation, etc.) to pass.
- Performs a Terraform **init/validate/plan** against the baseline config (Auth0 provider), surfacing plan output and errors back in the PR.

> **Note:** This job safeguards infra drift by ensuring what would deploy is visible during review, but **does not** apply changes on PRs.

### 5.3 Deployment Workflow – `.github/workflows/terraform-deploy.yml`
**Trigger:** `push` to `main` under `base/base-line/configs/**` (and manual dispatch).

**Behavior:**
- Uses environment `dev` and secrets `DEV_AUTH0_DOMAIN`, `DEV_AUTH0_CLIENT_ID`, `DEV_AUTH0_CLIENT_SECRET`.
- Runs Terraform `init/validate/plan/apply` using `base/terraform/` and the merged baseline configs.
- Publishes a summary (success/failure). Uploads plan as an artifact for audit.

### 5.4 Secret Verification – `.github/workflows/ci-smoke.yml`
**Trigger:** manual `workflow_dispatch`.

**Behavior:**
- Exchanges the configured M2M client credentials for an Auth0 **access token** to verify secrets are valid and the tenant is reachable.

> For now, deployments target the **dev** environment using credentials stored as environment secrets.

---

## 6) Terraform Deployment Model

- **Provider:** `auth0/auth0` (see `base/terraform/main.tf` / `variables.tf`).
- **Inputs:** Provided by GitHub environment secrets and the baseline config YAMLs (merged in the workflow prior to plan/apply or read by the TF code as local files if scripted).
- **Managed resources include (examples, see `main.tf`):**
  - Branding, database connection, Guardian/MFA policy, and app/client configuration derived from baseline inputs.
- **Outputs:** Useful outputs like database connection ID, MFA policy state, etc., via `output {}` blocks.

> **State:** Use a secure remote backend in production. (This POC may include local artifacts to persist TF state; for real environments configure Terraform Cloud, S3 + DynamoDB, etc.)

---

## 7) Configuration Data Flow

1. **Author edits** YAML files under `apps/`, `tenants/<env>/tenantX/`, or `base/base-line/`.
2. **PR opened** → GitHub Actions run:
   - **Path Guard** enforces ownership and environment boundaries immediately.
   - Depending on changed paths, **Conftest** validates against the correct Rego policies and standards.
3. **If PR checks pass**, reviewers (from CODEOWNERS) approve/merge.
4. On **merge to main**, `terraform-deploy.yml` plans and applies to the `dev` tenant using the configured M2M—emitting a summary and artifacts.

---

## 8) Enforcement Scenarios & Real-World Examples

- **Cross‑app edits blocked:** A member of `team-app1` changes `apps/app2/security.yml` → `path_guard.rego` denies with: _“Your team (app: app1) cannot modify files in app: app2.”_
- **Prod edits blocked:** Any non‑core change under `tenants/prod/**` → denied.
- **SPA security correctness:** An SPA must not use a confidential client auth method; standards enforce `token_endpoint_auth_method` of `none` and `response_types: ["code"]`.
- **PKCE & HTTPS by env:** In QA/Prod, `enforce_pkce: true` and `require_https: true` are mandatory for OIDC; in Dev some relaxations are allowed per `tenants/overlays/validators/app-oidc-standard.yml`.
- **JWT lifetimes & refresh token rotation:** Enforced via `base/tenants-common/tokens.yml` against app `tokens.yml`.

---

## 9) Extensibility & Future Enhancements

- **Add a new app:** Create `apps/<appN>/{security.yml,tokens.yml,orgs.yml}`. Update team mappings in `path_guard.rego` and CODEOWNERS for reviewers.
- **Add a new tenant:** Add `tenants/<env>/<tenantX>/*.yml`. The tenant overlay policy will auto‑detect env and validate.
- **Strengthen enterprise posture:** Update `overlays/shared-sec/identity_access.yml` and logic in `overlays/policies/shared_sec.rego`.
---

## 10) Policy Input Schema Reference

- **Path Guard (`path_guard.rego`):**
  ```json
  {
    "files": ["apps/app1/security.yml", "tenants/dev/tenantA/app-oidc.yml", "..."],
    "actor_teams": ["team-app1", "team-app1-reviewers"],
    "debug": false
  }
  ```

- **Baseline Validator (`baseline-validator.rego`):**
  ```yaml
  config:   # merged from base-line/configs
    auth-settings: {...}
    app-oidc: {...}
    risk-settings: {...}
    ux-settings: {...}
  standard: # merged from base-line/validators
    auth-settings: {... requirements ...}
    ...
  ```

- **Tenant Overlay (`auth0_validation.rego`):**
  ```yaml
  oidc: { issuer: "https://dev-..." }
  security: { allowed_origins: ["http://localhost:3000", ...], ... }
  branding: { logo_url: "https://.../qa/..." }
  ```

- **App Policy (`auth0_policy.rego`):**
  ```yaml
  security: {...}
  tokens: {...}
  orgs: {...}
  app_type: "spa" | "regular_web" | "native"
  ```

---

## 11) Operational Guidance & Governance Notes

- Keep reviewer teams in sync with CODEOWNERS and the `team_to_app` map in `path_guard.rego`.
- Prefer small, scoped PRs to make policy violations obvious and actionable.
- For real deployments, configure a secure Terraform backend and split environment deployments by environment with appropriate environment secrets.

### 11.1 Policy & Workflow File References
- **Policies:**
  - `base/policies/path_guard.rego`
  - `base/policies/auth0_policy.rego`
  - `base/base-line/policies/baseline-validator.rego`
  - `tenants/overlays/policies/auth0_validation.rego`
  - `overlays/policies/shared_sec.rego`
- **Standards:**
  - `base/base-line/validators/*.yaml`
  - `tenants/overlays/validators/*.yml`
  - `base/tenants-common/*.yml`
- **Configs:**
  - `base/base-line/configs/*.yml`
  - `apps/<app>/*.yml`
  - `tenants/<env>/<tenant>/*.yml`
- **Workflows:**
  - `.github/workflows/pr-checks.yml`
  - `.github/workflows/terraform-check.yml`
  - `.github/workflows/terraform-deploy.yml`
  - `.github/workflows/ci-smoke.yml`

---

## 12) Initial Setup & Environment Prerequisites

This section prepares GitHub and Auth0 so the CI policy gates and Terraform flows can run securely per environment.

### 12.1 Create GitHub Teams (RBAC Model)

Create the following teams in your GitHub org:

- **@uday-test/ciam-core**
  - Purpose: platform owners (full repo + prod controls).
  - Minimum permissions: Maintain (or Admin).

- **@uday-test/team-app1**
  - Purpose: app1 developers (dev-only app path).
  - Permissions: Write on repo.

- **@uday-test/team-app1-reviewers**
  - Purpose: required reviewers for app1 paths.
  - Permissions: Write.
  - This team is child of the parent team team-app1.

- **@uday-test/team-app2 / @uday-test/team-app2-reviewers**
  - Same as app1 for app2.

> Keep the names exactly as referenced in CODEOWNERS and `base/policies/path_guard.rego`.

#### Branch protection & required reviews

Protect **main** branch:
- Add classic branch protection rule
- Require PRs.
- Require CODEOWNERS reviews (e.g., 1–2 approvals).

---

### 12.2 Configure GitHub Environments & Secrets

Create GitHub **Environments**: `dev`, `qa`, `prod`. Add environment-scoped secrets:

#### Auth0 deployer M2M (per environment)
- `DEV_AUTH0_DOMAIN` / `QA_AUTH0_DOMAIN` / `PROD_AUTH0_DOMAIN`
  - Example: `tenant-dev.us.auth0.com`
- `DEV_AUTH0_CLIENT_ID` / `QA_AUTH0_CLIENT_ID` / `PROD_AUTH0_CLIENT_ID`
- `DEV_AUTH0_CLIENT_SECRET` / `QA_AUTH0_CLIENT_SECRET` / `PROD_AUTH0_CLIENT_SECRET`

#### Optional: smoke test-only client (if different than deployer)
- `DEV_SMOKE_CLIENT_ID`, `DEV_SMOKE_CLIENT_SECRET` (and equivalents for QA/PROD if you choose to run smoke there)

> Use **Environment secrets** (not repository secrets) so jobs run only with the minimum needed credentials for that environment.

---

### 12.3 Provision Auth0 M2M Clients (Per Environment)

In each Auth0 tenant (`dev` / `qa` / `prod`):

1. Create an M2M application **“Terraform Deployer – <env>”**.
2. Grant **Management API scopes** needed for resources you manage (principle of least privilege). Common examples:

```
read:clients, create:clients, update:clients
read:connections, create:connections, update:connections
read:tenant_settings, update:tenant_settings
read:guardian_factors, update:guardian_factors
read:branding, update:branding
```

3. Copy **Domain**, **Client ID**, **Client Secret** into the matching GitHub environment secrets above.
4. Validate with the smoke workflow (`ci-smoke.yml`) before enabling auto-deploys.

---

### 12.4 Set Organization Token (Fine-Grained PAT)

Some workflows (e.g., enriching reviewer/team checks or calling GitHub APIs beyond the default GITHUB_TOKEN capabilities) may need an org-scoped token.

**Configuration**

- **Secret name:** `ORG_TOKEN`
- **Location:** Store in the Organization secrets
- **Type:** Fine-grained PAT (preferred)
- **Owner:** Service or bot account
- **Access scopes:**
  - Read access to repository metadata
  - Read access to organization members
- **Repository access:** Restrict to `auth0-domain1` repo only

> Add `ORG_TOKEN` to retrieve the team memberships of the developer who raisd the PR.

---

### 12.5 Enforce Naming & Path Conventions

- **Teams** must match `CODEOWNERS` and `path_guard.rego` mappings:
  - `team-app1` ↔ paths: `/apps/app1/**`, `/tenants/dev/**`
  - `team-app2` ↔ paths: `/apps/app2/**`, `/tenants/dev/**`
  - `ciam-core` ↔ full repo
- **Environments:** `dev`, `qa`, `prod` (used in tenant overlays and policy env detection)
- **Secret names:** Must follow the `ENV_*` convention exactly as used in workflows.

---

### 12.6 Grant GitHub Action Permissions

- **Settings → Actions:**  
  - Workflow permissions: “Read and write” (needed to post checks, comments, artifacts).
  - Allow GitHub Actions to create and approve pull requests from GitHub Apps: optional.

---

### 12.7 Tooling Baseline & Version Matrix

| Tool | Version | Notes |
|------|----------|--------|
| Conftest | v0.62.0 | Used in workflows |
| yq | v4.44.3 | Scripts expect yq v4 CLI |
| Terraform | 1.6.x | Matches setup-terraform version |
| Rego | v1 | Align imports with Rego v1 syntax |

---

### 12.8 Validation Checklist (Pre-Deployment)

- [x] Teams created; membership set.
- [x] Branch protection on `main` with required checks & CODEOWNERS reviews.
- [x] GitHub Environments created with correct secrets per env.
- [x] Auth0 M2M created per env with least-privilege scopes and secrets saved.
- [x] (Optional) `ORG_TOKEN` secret set if org lookups are needed.
- [x] Smoke test workflow completes successfully.
- [x] PR checks block cross-app edits and prod edits by non-core members.

---
