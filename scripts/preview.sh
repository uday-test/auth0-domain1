#!/usr/bin/env bash
set -Eeuo pipefail

# ---------- config ----------
TENANT="${1:-tenantA}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
BASE_DIR="$ROOT_DIR/base/tenants-common"
OVERLAY_DIR="$ROOT_DIR/overlays/shared-sec"
TENANTS_DIR="$ROOT_DIR/tenants"
OUT_DIR="$ROOT_DIR/out"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------- helpers ----------
need_yq() {
  if ! command -v yq >/dev/null 2>&1; then
    echo "❌ Missing 'yq' (v4+). Install: https://github.com/mikefarah/yq#install" 1>&2
    exit 2
  fi
}

# deep merge (left→right)
merge_yaml() {
  local out="$1"; shift
  yq ea -P '. as $doc ireduce ({}; . * $doc )' "$@" >"$out"
}

# pretty + stable key order
sorted_to() { # sorted_to <in> <out>
  yq ea -P 'sort_keys(..)' "$1" >"$2"
}

mkout() { mkdir -p "$OUT_DIR/$1"; }

# numeric compare helper: effective must be <= baseline (i.e., as strict or stricter)
num_must_be_le() { # num_must_be_le "<label>" "<yq_path>"
  local label="$1" q="$2" base_val eff_val
  base_val="$(yq -r "$q // \"\"" "$BASELINE")"
  [[ -n "$base_val" && "$base_val" != "null" ]] || return 0
  eff_val="$(yq -r "$q // \"\"" "$EFF")"
  # if missing in effective, treat as 0 (stricter)
  [[ "$eff_val" =~ ^[0-9]+$ ]] || eff_val=0
  if (( eff_val > base_val )); then
    echo "❌ $ENV_NAME: $label=$eff_val weaker than baseline ($base_val)"
    ENFORCE_FAIL=1
  fi
}

# boolean must be true if baseline true
bool_must_be_true() { # bool_must_be_true "<label>" "<yq_path>"
  local label="$1" q="$2" b e
  b="$(yq -r "$q // \"\"" "$BASELINE")"
  [[ "$b" == "true" ]] || return 0
  e="$(yq -r "$q // \"false\"" "$EFF")"
  if [[ "$e" != "true" ]]; then
    echo "❌ $ENV_NAME: requires $label = true"
    ENFORCE_FAIL=1
  fi
}

# ---------- rendering ----------
render_env() {
  local env="$1"
  local base_merged="$TMP_DIR/${env}.base.yml"
  local eff_merged="$OUT_DIR/$env/$TENANT.effective.yml"
  local diff_out="$OUT_DIR/$env/$TENANT.diff.txt"

  echo "▶ Rendering $env for tenant $TENANT"
  mkout "$env"

  merge_yaml "$base_merged" "$BASE_DIR"/*.yml
  merge_yaml "$eff_merged"  "$BASE_DIR"/*.yml "$OVERLAY_DIR"/*.yml "$TENANTS_DIR/$env/$TENANT/config.yml"

  # stable sort + diff without process substitution (windows-safe)
  local base_sorted="$TMP_DIR/${env}.base.sorted.yml"
  local eff_sorted="$TMP_DIR/${env}.eff.sorted.yml"
  sorted_to "$base_merged" "$base_sorted"
  sorted_to "$eff_merged"  "$eff_sorted"
  diff -u "$base_sorted" "$eff_sorted" | sed '1,2d' >"$diff_out" || true

  echo "  • wrote $eff_merged"
  echo "  • wrote $diff_out"
}

cross_env_diffs() {
  printf "\n▶ Cross-env drift checks\n"
  local pairs=("dev qa" "qa prod" "dev prod")
  for p in "${pairs[@]}"; do
    set -- $p
    local a="$1" b="$2"
    local A="$OUT_DIR/$a/$TENANT.effective.yml"
    local B="$OUT_DIR/$b/$TENANT.effective.yml"
    if [[ -f "$A" && -f "$B" ]]; then
      local As="$TMP_DIR/${a}.sorted.yml"
      local Bs="$TMP_DIR/${b}.sorted.yml"
      local out="$OUT_DIR/${a}_vs_${b}.${TENANT}.diff.txt"
      sorted_to "$A" "$As"
      sorted_to "$B" "$Bs"
      diff -u "$As" "$Bs" | sed '1,2d' >"$out" || true
      echo "  • $out"
    fi
  done
}

# ---------- enforcement (deny PR if weaker than shared-sec) ----------
enforce_shared_sec() {
  echo
  echo "▶ Building shared-sec baseline"
  BASELINE="$TMP_DIR/baseline.yml"
  merge_yaml "$BASELINE" "$OVERLAY_DIR"/*.yml
  echo "  • merged baseline from overlays/shared-sec/*.yml"

  ENFORCE_FAIL=0

  for ENV_NAME in dev qa prod; do
    EFF="$OUT_DIR/$ENV_NAME/$TENANT.effective.yml"
    if [[ ! -f "$EFF" ]]; then
      echo "❌ $ENV_NAME: missing effective file $EFF"
      ENFORCE_FAIL=1
      continue
    fi
    echo "▶ Enforcing baseline on $ENV_NAME ($EFF)"

    # --- MFA factors (allow only these; disallow sms) ---
    mapfile -t FACTORS < <(yq -r '.identity_access.mfa.allowed_factors // .mfa.factors // [] | .[]' "$EFF" 2>/dev/null || true)
    # lowercase normalize
    for i in "${!FACTORS[@]}"; do FACTORS[$i]="${FACTORS[$i],,}"; done

    # required factors
    for req in authenticator_app webauthn-roaming; do
      if ! printf '%s\n' "${FACTORS[@]}" | grep -Eq "^${req}$"; then
        echo "❌ $ENV_NAME: required MFA factor '$req' missing"
        ENFORCE_FAIL=1
      fi
    done
    # banned + unknowns
    for f in "${FACTORS[@]}"; do
      if [[ "$f" == "sms" ]]; then
        echo "❌ $ENV_NAME: SMS MFA found"
        ENFORCE_FAIL=1
      elif [[ "$f" != "authenticator_app" && "$f" != "webauthn-roaming" ]]; then
        echo "❌ $ENV_NAME: MFA factor '$f' is not allowed by enterprise baseline"
        ENFORCE_FAIL=1
      fi
    done

    # --- Password policy must be >= baseline ---
    local base_min eff_min base_hist eff_hist
    base_min="$(yq -r '.identity_access.password_policy.min_length // ""' "$BASELINE")"
    eff_min="$(yq -r '.identity_access.password_policy.min_length // 0'  "$EFF")"
    if [[ -n "$base_min" && "$base_min" != "null" && "$eff_min" -lt "$base_min" ]]; then
      echo "❌ $ENV_NAME: password min_length $eff_min < baseline $base_min"
      ENFORCE_FAIL=1
    fi
    base_hist="$(yq -r '.identity_access.password_policy.history_count // ""' "$BASELINE")"
    eff_hist="$(yq -r '.identity_access.password_policy.history_count // 0'  "$EFF")"
    if [[ -n "$base_hist" && "$base_hist" != "null" && "$eff_hist" -lt "$base_hist" ]]; then
      echo "❌ $ENV_NAME: password history_count $eff_hist < baseline $base_hist"
      ENFORCE_FAIL=1
    fi

    # --- Required booleans (if true in baseline → must be true in effective) ---
    bool_must_be_true "security.breach_detection.enabled" '.security.breach_detection.enabled'
    bool_must_be_true "security.password_policy.require_numbers"   '.security.password_policy.require_numbers'
    bool_must_be_true "security.password_policy.require_symbols"   '.security.password_policy.require_symbols'
    bool_must_be_true "security.password_policy.require_uppercase" '.security.password_policy.require_uppercase'
    bool_must_be_true "security.password_policy.require_lowercase" '.security.password_policy.require_lowercase'
    bool_must_be_true "mfa.enabled" '.mfa.enabled'

    # --- Timeouts & TTLs: effective must be <= baseline (stricter or equal) ---
    num_must_be_le "session.idle_timeout_minutes" '.session.idle_timeout_minutes'
    num_must_be_le "session.absolute_timeout_hours" '.session.absolute_timeout_hours'
    num_must_be_le "tokens.access_token_ttl" '.tokens.access_token_ttl'
    num_must_be_le "tokens.id_token_ttl" '.tokens.id_token_ttl'
    num_must_be_le "tokens.refresh_token_ttl" '.tokens.refresh_token_ttl'
    num_must_be_le "tokens.refresh.lifetime_days" '.tokens.refresh.lifetime_days'
    num_must_be_le "tokens.refresh.inactivity_days" '.tokens.refresh.inactivity_days'
    num_must_be_le "tokens.refresh.leeway_days" '.tokens.refresh.leeway_days'

    # --- Logout URLs: effective must include all required enterprise URLs ---
    if yq -e '.general.allowed_logout_urls' "$BASELINE" >/dev/null 2>&1; then
      while IFS= read -r url; do
        [[ -z "$url" || "$url" == "null" ]] && continue
        if ! yq -r '.general.allowed_logout_urls[]? // empty' "$EFF" | grep -Fxq "$url"; then
          echo "❌ $ENV_NAME: missing required logout URL $url"
          ENFORCE_FAIL=1
        fi
      done < <(yq -r '.general.allowed_logout_urls[]? // empty' "$BASELINE")
    fi
  done

  return "$ENFORCE_FAIL"
}

main() {
  need_yq

  # fail fast if globs would be empty (prevents yq waiting on stdin)
  shopt -s nullglob
  base_files=( "$BASE_DIR"/*.yml );  [[ ${#base_files[@]}    -gt 0 ]] || { echo "❌ No YAML in $BASE_DIR"; exit 1; }
  overlay_files=( "$OVERLAY_DIR"/*.yml ); [[ ${#overlay_files[@]} -gt 0 ]] || { echo "❌ No YAML in $OVERLAY_DIR"; exit 1; }
  shopt -u nullglob

  # render each env
  for env in dev qa prod; do
    if [[ ! -f "$TENANTS_DIR/$env/$TENANT/config.yml" ]]; then
      echo "❌ Missing $TENANTS_DIR/$env/$TENANT/config.yml" 1>&2
      exit 1
    fi
    render_env "$env"
  done

  cross_env_diffs

  echo
  echo "▶ Enforcing shared-sec baseline"
  if ! enforce_shared_sec; then
    echo "❌ Enforcement failed: effective config is weaker than shared-sec baseline"
    exit 1
  fi
  echo "✅ Enforcement passed"
}

main "$@"
