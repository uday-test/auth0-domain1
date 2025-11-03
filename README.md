# Auth0-Domain1 – Repository & Policy-Driven Documentation

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
    - [12.1 Create GitHub Teams (RBAC Model)](#121-create-github-teams-rbac-model)
    - [12.2 Configure GitHub Environments & Secrets](#122-configure-github-environments--secrets)
    - [12.3 Provision Auth0 M2M Clients (Per Environment)](#123-provision-auth0-m2m-clients-per-environment)
    - [12.4 Set Organization Token (Fine-Grained PAT)](#124-set-organization-token-fine-grained-pat)
    - [12.5 Enforce Naming & Path Conventions](#125-enforce-naming--path-conventions)
    - [12.6 Grant GitHub Action Permissions](#126-grant-github-action-permissions)
    - [12.7 Tooling Baseline & Version Matrix](#127-tooling-baseline--version-matrix)
    - [12.8 Validation Checklist (Pre-Deployment)](#128-validation-checklist-pre-deployment)
13. [Achievements & Outcomes](#13-achievements--outcomes)

---

## 1) Overview & Objectives

This repository codifies **Auth0 tenant and application configuration**, along with **security and compliance standards**, entirely as code.  
It integrates **policy-as-code**, **CI/CD automation**, and **Terraform-based infrastructure management** to ensure every configuration change is reviewable, validated, and reproducible.

It uses:

- **[Rego policies](#4-standards-framework--policy-enforcement)** with **Conftest** to validate YAML configuration files against defined standards before deployment (see [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).  
- **[GitHub Actions workflows](#5-continuous-integration--delivery-pipelines-cicd)** to enforce [path ownership and RBAC](#3-access-control--path-governance), validate [baseline configurations](#41-baseline-standards-vs-baseline-configurations), [tenant overlays](#42-environment-specific-tenant-standards-overlays), and [application-level settings](#43-application-level-standards--validations), while automating Terraform checks and deployments (see [Sections 5.2–5.3](#5-continuous-integration--delivery-pipelines-cicd)).  
- **[Terraform automation](#6-terraform-deployment-model)** to apply validated and approved baseline configurations directly to Auth0 tenants using environment-specific M2M credentials.

> Primary CI/CD jobs reside in [`.github/workflows/`](#5-continuous-integration--delivery-pipelines-cicd), and policies live under  
> [`base/**`](#41-baseline-standards-vs-baseline-configurations), [`tenants/**`](#42-environment-specific-tenant-standards-overlays), and [`overlays/**`](#44-enterprise-shared-security-overlay). Refer to [Section 11.1](#111-policy--workflow-file-references) for exact file paths.

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

> See [Section 5](#5-continuous-integration--delivery-pipelines-cicd) for workflow behavior and [Section 11.1](#111-policy--workflow-file-references) for file references.

---

## 3) Access Control & Path Governance

### 3.1 CODEOWNERS Review Model
- File: `CODEOWNERS`
- Default owner: `@uday-test/ciam-core` for everything.
- App folders: `/apps/app1/` → `@uday-test/team-app1-reviewers`, `/apps/app2/` → `@uday-test/team-app2-reviewers`.
- CI workflows, base configs, policies, catalogs, scripts, and CODEOWNERS itself → `@uday-test/ciam-core`.

This ensures the right reviewers must approve changes in app- or platform-owned paths before merging (see [Section 5.1 – Path Guard](#51-pr-validation-workflow--githubworkflowspr-checksyml)).

### 3.2 PR Path Guard Policy
- File: `base/policies/path_guard.rego` (see [Section 11.1](#111-policy--workflow-file-references))
- Inputs: (provided by the workflow) changed `files[]`, actor `actor_teams[]`, and optional `env` (constructed in [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).
- Behavior:
  - Maps teams ↔ apps (`team-app1`, `team-app2`, including `*-reviewers`).
  - **Core bypass:** `ciam-core` can touch anything.
  - **App scoping:** App teams may only change their own app under `apps/<app>/...`.
  - **Environment scoping:**  Developer teams are limited to `tenants/dev/...`; touching `tenants/prod/...` is always denied.

**Why it matters:** Improper cross-app changes or unauthorized env changes are blocked **before** any policy validations (see [Section 4](#4-standards-framework--policy-enforcement)) or Terraform stages (see [Section 5.2](#52-terraform-plan-validation--githubworkflowsterraform-checkyml) and [5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml)) run.

---

## 4) Standards Framework & Policy Enforcement

### 4.1 Baseline Standards vs Baseline Configurations
- **Standards (authoritative expectations):**
  - `base/base-line/validators/*.yaml` (4 files) define required schema/values for:
    - `app-oidc-standard`, `auth-settings-standard`, `risk-settings-standard`, and `ux-settings-standard`.
- **Configs (intended baseline values):**
  - `base/base-line/configs/*.yml` provide actual baseline values.
- **Policy:** `base/base-line/policies/baseline-validator.rego`
  - Conftest merges all baseline config files and all standard files into a single input document (merged in [Section 5.1 – baseline-config-validation](#51-pr-validation-workflow--githubworkflowspr-checksyml)):
    ```yaml
    config:   # merged from base-line/configs/*.yml
    standard: # merged from base-line/validators/*.yaml
    ```
  - The policy checks **required fields exist**, **must_equal**, **min/max**, etc., at multiple nesting levels.

> Outcome: If a baseline config drifts from standard, PR fails in “Baseline Config Validation” (see [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).

### 4.2 Environment-Specific Tenant Standards (Overlays)
- **Standards:** `tenants/overlays/validators/*.yml` encode **dev/qa/prod** specific rules (e.g., grant types, PKCE, HTTPS, UX restrictions, risk controls).
- **Policy:** `tenants/overlays/policies/auth0_validation.rego`
  - Detects `env` from inputs (issuer patterns, allowed origins, branding URL hints) and applies the correct env’s rules (invoked in [Section 5.1 – tenant-config-validation](#51-pr-validation-workflow--githubworkflowspr-checksyml)).
  - Examples enforced:
    - `require_https`: dev can be relaxed, qa/prod must be true.
    - `enforce_pkce`: required in qa/prod, relaxed in dev depending on client type.
    - Allowed `grant_types` by env; implicit is allowed only in dev (if configured).
    - Higher level environmetns require the risk setttings and can be ignored in the lower environment settings like dev.

> Outcome: Edits under `tenants/<env>/<tenantX>/*.yml` are validated against **that env’s** standards (see [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).

### 4.3 Application-Level Standards & Validations
- **Standards (common):** `base/tenants-common/*.yml`
  - `security.yml` (e.g., allowed grant types and response types per `spa`, `regular_web`, `native`, CORS rules, OIDC conformance, token endpoint auth methods, cross-origin auth expectations, etc.)
  - `tokens.yml` (JWT alg/lifetimes, refresh token rotation/absolute lifetime, etc.)
  - `orgs.yml` (organization usage rules and behaviors)
- **Configs (per app):** `apps/<app>/{security.yml,tokens.yml,orgs.yml}`
- **Policy:** `base/policies/auth0_policy.rego`
  - Inputs: `input.security`, `input.tokens`, `input.orgs`
  - Validates app configs against common standards, e.g.:
    - **Grant types**: SPA → `authorization_code`, forbid implicit in enterprise prod context; Regular Web → `authorization_code` and proper client auth; Native → no client secret.
    - **Response types** and **CORS/web origins** alignment with client type.
    - **JWT/refresh token** lifetimes and rotation.
    - **Org behaviors** alignment (`allow`, prompt behavior).

> Outcome: PRs that touch `apps/<app>/*` are auto-validated against applciation level standards (see [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).

### 4.4 Enterprise Shared Security Overlay
- **Standards:** `overlays/shared-sec/identity_access.yml` (e.g., min password length, history, and MFA factors to be enabled/disabled enterprise-wide)
- **Policy:** `overlays/policies/shared_sec.rego`
  - Merges/normalizes required factors and checks identity access settings meet or exceed enterprise requirements (run with shared checks in [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).

> Outcome: A single place to harden shared/enterprise-wide auth posture beyond app or tenant specifics.

---

## 5) Continuous Integration & Delivery Pipelines (CI/CD)

### 5.1 PR Validation Workflow – `.github/workflows/pr-checks.yml`
**Triggers:** `pull_request` to `main` (opened, reopened, synchronize, edited, ready_for_review) and manual `workflow_dispatch`.

**Jobs (in order):**

1) **setup**  
   - Installs/caches **Conftest** and **yq** binaries for later jobs (used across [Sections 4.1–4.4](#4-standards-framework--policy-enforcement)).

2) **path-guard** (needs: setup)  
   - Computes changed files (`git diff` base..head).  
   - Collects actor’s teams and constructs **Conftest input** with `files[]` + `actor_teams[]`.  
   - Runs `base/policies/path_guard.rego` to **block**:
     - Cross-app edits (e.g., team-app1 trying to touch `apps/app2/*`).
     - Any edits touching `tenants/prod/*` by non-core teams.
     - Edits outside `tenants/dev/*` for non-core teams.  
   - See model in [Section 3.2](#32-pr-path-guard-policy).

3) **baseline-config-validation** (needs: setup, path-guard)  
   - Detects if baseline files under `base/base-line/{configs,validators}` changed in the PR; if not, it **skips**.  
   - If changed, merges the four **configs** and four **standards** via `yq` into a **single input YAML** and runs Conftest against `base/base-line/policies/baseline-validator.rego`.  
   - Standards vs configs approach in [Section 4.1](#41-baseline-standards-vs-baseline-configurations).

4) **tenant-config-validation** (needs: setup, path-guard)  
   - Detects whether PR touches any `tenants/<env>/tenant*/{app-oidc,auth-settings,risk-settings,ux-settings}.yml`.  
   - For each environment found (`dev`, `qa`, `prod`), merges tenant files and validates with `tenants/overlays/policies/auth0_validation.rego` against the env-aware standards in `tenants/overlays/validators/*`.  
   - Details in [Section 4.2](#42-environment-specific-tenant-standards-overlays).

5) **app-config-validation** (needs: setup, path-guard)  
   - Detects whether PR touches `apps/*/(tokens|security|orgs).yml`.  
   - Iterates each `apps/<app>/` directory, infers **app_type** (`spa`, `regular_web`, `native`), and validates the three app files with `base/policies/auth0_policy.rego` against `base/tenants-common/*` standards.  
   - Standards in [Section 4.3](#43-application-level-standards--validations).

> **Fail-fast behavior:** Any denial from policy causes the job to fail and the PR check to turn red. See also Terraform gates in [Section 5.2](#52-terraform-plan-validation--githubworkflowsterraform-checkyml).

### 5.2 Terraform Plan Validation – `.github/workflows/terraform-check.yml`
**Trigger:** `pull_request` to `main` when paths under `base/base-line/configs/**` change.

**Behavior:**
- Waits for the PR checks above (Path Guard + Baseline Validation, etc.) to pass (see [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).  
- Performs a Terraform **init/validate/plan** against the baseline config (Auth0 provider), surfacing plan output and errors back in the PR.

> **Note:** This job safeguards infra drift by ensuring what would deploy is visible during review, but **does not** apply changes on PRs. Application to tenants is covered in [Section 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml) and modeled in [Section 6](#6-terraform-deployment-model).

### 5.3 Deployment Workflow – `.github/workflows/terraform-deploy.yml`
**Trigger:** `push` to `main` under `base/base-line/configs/**` (and manual dispatch).

**Behavior:**
- Uses environment `dev` and secrets `DEV_AUTH0_DOMAIN`, `DEV_AUTH0_CLIENT_ID`, `DEV_AUTH0_CLIENT_SECRET` (configured in [Section 12.2](#122-configure-github-environments--secrets)).  
- Runs Terraform `init/validate/plan/apply` using `base/terraform/` and the merged baseline configs.  
- Publishes a summary (success/failure). Uploads plan as an artifact for audit.

> For provider and state model, see [Section 6](#6-terraform-deployment-model).

### 5.4 Secret Verification – `.github/workflows/ci-smoke.yml`
**Trigger:** manual `workflow_dispatch`.

**Behavior:**
- Exchanges the configured M2M client credentials for an Auth0 **access token** to verify secrets are valid and the tenant is reachable (secrets defined in [Section 12.2](#122-configure-github-environments--secrets)).

> For now, deployments target the **dev** environment using credentials stored as environment secrets (see [Section 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml)).

---

## 6) Terraform Deployment Model

- **Provider:** `auth0/auth0` (see `base/terraform/main.tf` / `variables.tf`; deployed by [Section 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml)).  
- **Inputs:** Provided by GitHub environment secrets and the baseline config YAMLs (merged in the workflow after codeowner approval prior to plan/apply as per [Section 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml)).  
- **Managed resources include (examples, see `main.tf`):**
  - Branding, database connection, Guardian/MFA policy, and app/client configuration derived from baseline inputs.
- **Outputs:** Useful outputs like database connection ID, MFA policy state, etc., via `output {}` blocks.

> **State:** Use a secure remote backend in production. (This POC may include local artifacts to persist TF state; for real environments configure Terraform Cloud, S3 + DynamoDB, etc.) And for now we are deploying it to the dev environemnt (controlled by [Section 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml)).

---

## 7) Configuration Data Flow

1. **Developer edits** YAML files under `apps/`, `tenants/<env>/tenantX/`, or `base/base-line/`.  
2. **PR opened** → GitHub Actions run:
   - **Path Guard** enforces ownership and environment boundaries immediately (see [Section 3.2](#32-pr-path-guard-policy) and job in [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).
   - Depending on changed paths, **Conftest** validates against the correct Rego policies and standards (see [Section 4](#4-standards-framework--policy-enforcement)).
3. **If PR checks pass**, reviewers (from CODEOWNERS in [Section 3.1](#31-codeowners-review-model)) approve/merge.
4. On **merge to main**, `terraform-deploy.yml` plans and applies to the `dev` tenant using the configured M2M—emitting a summary and artifacts (see [Section 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml)).

---

## 8) Enforcement Scenarios & Real-World Examples

- **Cross-app edits blocked:** A member of `team-app1` changes `apps/app2/security.yml` → `path_guard.rego` denies with: _“Your team (app: app1) cannot modify files in app: app2.”_ (see [Section 3.2](#32-pr-path-guard-policy)).
- **PKCE & HTTPS by env:** In QA/Prod, `enforce_pkce: true` and `require_https: true` are mandatory for OIDC; in Dev some relaxations are allowed per `tenants/overlays/validators/app-oidc-standard.yml` (see [Section 4.2](#42-environment-specific-tenant-standards-overlays)).
- **Prod edits blocked:** Any app developer change under `tenants/prod/**` → denied (see [Section 3.2](#32-pr-path-guard-policy)).  
- **SPA security correctness:** An SPA must not use a confidential client auth method; standards enforce `token_endpoint_auth_method` of `none` and `response_types: ["code"]` (validated in [Section 4.3](#43-application-level-standards--validations)).  
- **JWT lifetimes & refresh token rotation:** Enforced via `base/tenants-common/tokens.yml` against app `tokens.yml` (see [Section 4.3](#43-application-level-standards--validations)).

---

## 9) Extensibility & Future Enhancements

- **Add a new app:** Create `apps/<appN>/{security.yml,tokens.yml,orgs.yml}`. Update team mappings in `path_guard.rego` and CODEOWNERS for reviewers (see [Sections 3.1](#31-codeowners-review-model) and [3.2](#32-pr-path-guard-policy)).  
- **Add a new tenant:** Add `tenants/<env>/<tenantX>/*.yml`. The tenant overlay policy will auto-detect env and validate (see [Section 4.2](#42-environment-specific-tenant-standards-overlays) and job in [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).  
- **Strengthen enterprise posture:** Update `overlays/shared-sec/identity_access.yml` and logic in `overlays/policies/shared_sec.rego` (see [Section 4.4](#44-enterprise-shared-security-overlay)).

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
  > Produced and consumed during [Section 5.1 – path-guard](#51-pr-validation-workflow--githubworkflowspr-checksyml).

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
  > Merged and validated in [Section 5.1 – baseline-config-validation](#51-pr-validation-workflow--githubworkflowspr-checksyml) using the model in [Section 4.1](#41-baseline-standards-vs-baseline-configurations).

- **Tenant Overlay (`auth0_validation.rego`):**
  ```yaml
  oidc: { issuer: "https://dev-..." }
  security: { allowed_origins: ["http://localhost:3000", ...], ... }
  branding: { logo_url: "https://.../qa/..." }
  ```
  > Evaluated in [Section 5.1 – tenant-config-validation](#51-pr-validation-workflow--githubworkflowspr-checksyml) per env rules in [Section 4.2](#42-environment-specific-tenant-standards-overlays).

- **App Policy (`auth0_policy.rego`):**
  ```yaml
  security: {...}
  tokens: {...}
  orgs: {...}
  app_type: "spa" | "regular_web" | "native"
  ```
  > Evaluated in [Section 5.1 – app-config-validation](#51-pr-validation-workflow--githubworkflowspr-checksyml) using standards in [Section 4.3](#43-application-level-standards--validations).

---

## 11) Operational Guidance & Governance Notes

- Keep reviewer teams in sync with CODEOWNERS and the `team_to_app` map in `path_guard.rego` (see [Sections 3.1](#31-codeowners-review-model) and [3.2](#32-pr-path-guard-policy)).  
- Prefer small, scoped PRs to make policy violations obvious and actionable (caught in [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).  
- For real deployments, configure a secure Terraform backend and split environment deployments by environment with appropriate environment secrets (see [Sections 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml) and [12.2](#122-configure-github-environments--secrets)).

### 11.1 Policy & Workflow File References
- **Policies:**
  - `base/policies/path_guard.rego` (see [Section 3.2](#32-pr-path-guard-policy))
  - `base/policies/auth0_policy.rego` (see [Section 4.3](#43-application-level-standards--validations))
  - `base/base-line/policies/baseline-validator.rego` (see [Section 4.1](#41-baseline-standards-vs-baseline-configurations))
  - `tenants/overlays/policies/auth0_validation.rego` (see [Section 4.2](#42-environment-specific-tenant-standards-overlays))
  - `overlays/policies/shared_sec.rego` (see [Section 4.4](#44-enterprise-shared-security-overlay))
- **Standards:**
  - `base/base-line/validators/*.yaml` (see [Section 4.1](#41-baseline-standards-vs-baseline-configurations))
  - `tenants/overlays/validators/*.yml` (see [Section 4.2](#42-environment-specific-tenant-standards-overlays))
  - `base/tenants-common/*.yml` (see [Section 4.3](#43-application-level-standards--validations))
- **Configs:**
  - `base/base-line/configs/*.yml` (see [Section 4.1](#41-baseline-standards-vs-baseline-configurations))
  - `apps/<app>/*.yml` (see [Section 4.3](#43-application-level-standards--validations))
  - `tenants/<env>/<tenant>/*.yml` (see [Section 4.2](#42-environment-specific-tenant-standards-overlays))
- **Workflows:**
  - `.github/workflows/pr-checks.yml` (see [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml))
  - `.github/workflows/terraform-check.yml` (see [Section 5.2](#52-terraform-plan-validation--githubworkflowsterraform-checkyml))
  - `.github/workflows/terraform-deploy.yml` (see [Section 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml))
  - `.github/workflows/ci-smoke.yml` (see [Section 5.4](#54-secret-verification--githubworkflowsci-smokeyml))

---

## 12) Initial Setup & Environment Prerequisites

This section prepares GitHub and Auth0 so the CI policy gates and Terraform flows can run securely per environment (used by [Section 5](#5-continuous-integration--delivery-pipelines-cicd)).

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

> Keep the names exactly as referenced in CODEOWNERS and `base/policies/path_guard.rego` (see [Sections 3.1–3.2](#3-access-control--path-governance)).

#### Branch protection & required reviews

Protect **main** branch:
- Add classic branch protection rule
- Require PRs.
- Require CODEOWNERS reviews (e.g., 1–2 approvals).  
See how this integrates with checks in [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml).

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

> Use **Environment secrets** so jobs run only with the minimum needed credentials for that environment (consumed by [Sections 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml) and [5.4](#54-secret-verification--githubworkflowsci-smokeyml)).

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
4. Validate with the smoke workflow (`ci-smoke.yml`) before enabling auto-deploys (see [Section 5.4](#54-secret-verification--githubworkflowsci-smokeyml)).

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

> Add `ORG_TOKEN` to retrieve the team memberships of the developer who raisd the PR (used in [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).

---

### 12.5 Enforce Naming & Path Conventions

- **Teams** must match `CODEOWNERS` and `path_guard.rego` mappings:
  - `team-app1` ↔ paths: `/apps/app1/**`, `/tenants/dev/**`
  - `team-app2` ↔ paths: `/apps/app2/**`, `/tenants/dev/**`
  - `ciam-core` ↔ full repo
- **Environments:** `dev`, `qa`, `prod` (used in tenant overlays and policy env detection; see [Section 4.2](#42-environment-specific-tenant-standards-overlays))
- **Secret names:** Must follow the `ENV_*` convention exactly as used in workflows (consumed in [Section 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml)).

---

### 12.6 Grant GitHub Action Permissions

- **Settings → Actions:**  
  - Workflow permissions: “Read and write” (needed to post checks, comments, artifacts).
  - Allow GitHub Actions to create and approve pull requests from GitHub Apps: optional.

> Required for workflows in [Section 5](#5-continuous-integration--delivery-pipelines-cicd).

---

### 12.7 Tooling Baseline & Version Matrix

| Tool | Version | Notes |
|------|----------|--------|
| Conftest | v0.62.0 | Used in workflows (see [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)) |
| yq | v4.44.3 | Scripts expect yq v4 CLI (see [Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)) |
| Terraform | 1.6.0 | Matches setup-terraform version (see [Sections 5.2–5.3](#5-continuous-integration--delivery-pipelines-cicd)) |
| Rego | v1 | Align imports with Rego v1 syntax (policies in [Section 4](#4-standards-framework--policy-enforcement)) |

---

### 12.8 Validation Checklist (Pre-Deployment)

- [x] Teams created; membership set (see [Section 12.1](#121-create-github-teams-rbac-model)).  
- [x] Branch protection on `main` with required checks & CODEOWNERS reviews (see [Sections 3.1](#31-codeowners-review-model) and [5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).  
- [x] GitHub Environments created with correct secrets per env (see [Section 12.2](#122-configure-github-environments--secrets)).  
- [x] Auth0 M2M created per env with least-privilege scopes and secrets saved (see [Section 12.3](#123-provision-auth0-m2m-clients-per-environment)).  
- [x] `ORG_TOKEN` secret set to retrieve the team memberships (see [Section 12.4](#124-set-organization-token-fine-grained-pat)).  
- [x] Smoke test workflow completes successfully (see [Section 5.4](#54-secret-verification--githubworkflowsci-smokeyml)).  
- [x] PR checks block cross-app edits and prod edits by non-core members (see [Sections 3.2](#32-pr-path-guard-policy) and [5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).

---
## 13) Achievements & Outcomes

 ####  Access Governance Achievements
- **Cross-application access controls enforced**: Non-core teams cannot modify other apps’ paths (e.g., `team-app1` → `apps/app2/**` denied) via [Path Guard](#32-pr-path-guard-policy) and CODEOWNERS reviews in [Section 3.1](#31-codeowners-review-model).
- **Environment guardrails**: Non-core edits to `tenants/prod/**` are blocked; non-core contribution is scoped to `tenants/dev/**` (see [Section 3.2](#32-pr-path-guard-policy)).
- **Clear separation of duties**: Platform team (`ciam-core`) retains override for platform paths and protected workflows ([Section 3](#3-access-control--path-governance)).

 ####  Policy Enforcement Achievements
- **Baseline vs. Standards drift prevention**: Baseline configs are continuously checked against authoritative standards ([Section 4.1](#41-baseline-standards-vs-baseline-configurations)) during PRs ([Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).
- **Environment-aware tenant validation**: Dev/QA/Prod overlays enforce HTTPS, PKCE, grant types, and risk controls contextually ([Section 4.2](#42-environment-specific-tenant-standards-overlays)).
- **Application-level conformance**: SPA/Regular Web/Native clients validated for grant/response types, CORS, token auth method, and token lifetimes ([Section 4.3](#43-application-level-standards--validations)).
- **Enterprise overlay hardening**: Shared identity & access rules (password/MFA) applied consistently across tenants ([Section 4.4](#44-enterprise-shared-security-overlay)).

 ####  CI/CD Automation Achievements
- **Fail-fast PR gate**: Conftest + Rego policies run on every PR to surface violations early ([Section 5.1](#51-pr-validation-workflow--githubworkflowspr-checksyml)).
- **Controlled deployments**: Auto-apply to `dev` on merge with environment-scoped secrets and audit artifacts ([Section 5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml)).
- **Credential sanity checks**: On-demand smoke test validates M2M credentials and tenant reachability ([Section 5.4](#54-secret-verification--githubworkflowsci-smokeyml)).

 ####  Security & Compliance Outcomes
- **Immutable reviews & auditability**: CODEOWNERS + branch protection + workflow artifacts produce a traceable approval and execution trail ([Sections 3.1](#31-codeowners-review-model), [5.3](#53-deployment-workflow--githubworkflowsterraform-deployyml)).
- **Standards as code**: Centralized YAML standards plus policy-as-code reduce manual review variance ([Section 4](#4-standards-framework--policy-enforcement)).

#### Operational Efficiency
- **Single-source repo structure** clearly separates baseline, overlays, and app configs for easier ownership and scaling ([Section 2](#2-repository-architecture--folder-layout)).
- **Low-friction onboarding**: Adding apps/tenants is a repeatable pattern with pre-wired validation paths ([Section 9](#9-extensibility--future-enhancements)).
- **Reduced review noise**: Path Guard eliminates irrelevant reviewer pings and cross-team edit churn ([Section 3.2](#32-pr-path-guard-policy)).

