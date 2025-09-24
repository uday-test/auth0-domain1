#!/usr/bin/env bash
set -Eeuo pipefail

TENANT="${1:-tenantA}"
CI_MODE="${CI_MODE:-false}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
BASE_DIR="$ROOT_DIR/base/tenants-common"
OVERLAY_DIR="$ROOT_DIR/overlays/shared-sec"
TENANTS_DIR="$ROOT_DIR/tenants"
OUT_DIR="$ROOT_DIR/out"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

YQ_TIMEOUT_SECS="${YQ_TIMEOUT_SECS:-20}"

# Colors for output (disabled in CI)
if [[ "$CI_MODE" == "true" ]]; then
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  NC=""
else
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  NC='\033[0m' # No Color
fi

# Violation tracking for CI summary
VIOLATIONS=()
VIOLATION_COUNT=0

# Track violations for reporting
track_violation() {
  local violation="$1"
  VIOLATIONS+=("$violation")
  ((VIOLATION_COUNT++))
  echo -e "${RED}❌${NC} $violation"
}

# Report success
report_success() {
  local message="$1"
  echo -e "${GREEN}✅${NC} $message"
}

# Log enforcement results for CI
log_enforcement_result() {
  local env="$1"
  local result="$2"
  local message="$3"
  
  if [[ "$result" == "pass" ]]; then
    report_success "$env: $message"
  else
    track_violation "$env: $message"
  fi
}

# ---------- helpers ----------
need_yq() {
  if ! command -v yq >/dev/null 2>&1; then
    echo -e "${RED}❌${NC} Missing 'yq'. Install v4+: https://github.com/mikefarah/yq#install" 1>&2
    exit 2
  fi
  local ver
  ver="$(yq --version 2>/dev/null || true)"
  if ! grep -Eq 'version v?4\.' <<<"$ver"; then
    echo -e "${RED}❌${NC} yq v4+ required. Found: $ver" 1>&2
    exit 2
  fi
}

# deep merge (left→right)
merge_yaml() { # merge_yaml <out> <files...>
  local out="$1"; shift
  timeout "$YQ_TIMEOUT_SECS" yq ea -P '. as $doc ireduce ({}; . * $doc )' "$@" >"$out"
}

# pretty + stable key order
sorted_to() { # sorted_to <in> <out>
  timeout "$YQ_TIMEOUT_SECS" yq ea -P 'sort_keys(..)' "$1" >"$2"
}

mkout() { mkdir -p "$OUT_DIR/$1"; }

# numeric compare helper: effective must be >= baseline (i.e., as strict or stricter)
num_must_be_ge() { # num_must_be_ge "<label>" "<yq_path>"
  local label="$1" q="$2" base_val eff_val
  base_val="$(timeout "$YQ_TIMEOUT_SECS" yq -r "$q // \"\"" "$BASELINE")"
  [[ -n "$base_val" && "$base_val" != "null" ]] || return 0
  eff_val="$(timeout "$YQ_TIMEOUT_SECS" yq -r "$q // \"\"" "$EFF")"
  [[ "$eff_val" =~ ^[0-9]+$ ]] || eff_val=0
  if (( eff_val < base_val )); then
    track_violation "$ENV_NAME: $label=$eff_val weaker than baseline ($base_val)"
  fi
}

# boolean must be true if baseline true
bool_must_be_true() { # bool_must_be_true "<label>" "<yq_path>"
  local label="$1" q="$2" b e
  b="$(timeout "$YQ_TIMEOUT_SECS" yq -r "$q // \"\"" "$BASELINE")"
  [[ "$b" == "true" ]] || return 0
  e="$(timeout "$YQ_TIMEOUT_SECS" yq -r "$q // \"false\"" "$EFF")"
  if [[ "$e" != "true" ]]; then
    track_violation "$ENV_NAME: requires $label = true"
  fi
}

# ---------- rendering ----------
render_env() {
  local env="$1"
  local base_merged="$TMP_DIR/${env}.base.yml"
  local eff_merged="$OUT_DIR/$env/$TENANT.effective.yml"
  local diff_out="$OUT_DIR/$env/$TENANT.diff.txt"

  echo -e "${BLUE}▶${NC} Rendering $env for tenant $TENANT"
  mkout "$env"

  # Use pre-resolved arrays (no empty globs reaching yq)
  merge_yaml "$base_merged" "${BASE_FILES[@]}"
  merge_yaml "$eff_merged"  "${BASE_FILES[@]}" "${OVERLAY_FILES[@]}" "$TENANTS_DIR/$env/$TENANT/config.yml"

  # stable sort + diff (windows-safe)
  local base_sorted="$TMP_DIR/${env}.base.sorted.yml"
  local eff_sorted="$TMP_DIR/${env}.eff.sorted.yml"
  sorted_to "$base_merged" "$base_sorted"
  sorted_to "$eff_merged"  "$eff_sorted"
  diff -u "$base_sorted" "$eff_sorted" | sed '1,2d' >"$diff_out" || true

  echo "  • wrote $eff_merged"
  echo "  • wrote $diff_out"
}

cross_env_diffs() {
  printf "\n${BLUE}▶${NC} Cross-env drift checks\n"
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

# ---------- enforcement ----------
enforce_shared_sec() {
  echo
  echo -e "${BLUE}▶${NC} Building shared-sec baseline"
  BASELINE="$TMP_DIR/baseline.yml"
  merge_yaml "$BASELINE" "${OVERLAY_FILES[@]}"
  echo "  • merged baseline from overlays/shared-sec/*.yml"

  for ENV_NAME in dev qa prod; do
    EFF="$OUT_DIR/$ENV_NAME/$TENANT.effective.yml"
    if [[ ! -f "$EFF" ]]; then
      track_violation "$ENV_NAME: missing effective file $EFF"
      continue
    fi
    echo -e "${BLUE}▶${NC} Enforcing baseline on $ENV_NAME ($EFF)"

    # --- MFA factors (Auth0 format) ---
    mapfile -t ENABLED_FACTORS < <(timeout "$YQ_TIMEOUT_SECS" yq -r '.guardianMfaPolicy.factors[]? | select(.enabled == true) | .name' "$EFF" 2>/dev/null || true)

    # Check required factors are enabled
    for req in otp webauthn-roaming; do
      found=false
      for factor in "${ENABLED_FACTORS[@]}"; do
        if [[ "$factor" == "$req" ]]; then
          found=true
          break
        fi
      done
      if [[ "$found" == "false" ]]; then
        track_violation "$ENV_NAME: required MFA factor '$req' missing"
      fi
    done
    
    # Check SMS is NOT enabled
    for factor in "${ENABLED_FACTORS[@]}"; do
      if [[ "$factor" == "sms" ]]; then
        track_violation "$ENV_NAME: SMS MFA factor is enabled (should be disabled)"
      fi
    done

    # --- Password policy thresholds (Auth0 format) ---
    local base_min eff_min base_hist eff_hist
    base_min="$(timeout "$YQ_TIMEOUT_SECS" yq -r '.passwordPolicy.length.min // ""' "$BASELINE")"
    eff_min="$(timeout "$YQ_TIMEOUT_SECS" yq -r '.passwordPolicy.length.min // 0'  "$EFF")"
    if [[ -n "$base_min" && "$base_min" != "null" && "$eff_min" -lt "$base_min" ]]; then
      track_violation "$ENV_NAME: password min_length $eff_min < baseline $base_min"
    fi
    base_hist="$(timeout "$YQ_TIMEOUT_SECS" yq -r '.passwordPolicy.history // ""' "$BASELINE")"
    eff_hist="$(timeout "$YQ_TIMEOUT_SECS" yq -r '.passwordPolicy.history // 0'  "$EFF")"
    if [[ -n "$base_hist" && "$base_hist" != "null" && "$eff_hist" -lt "$base_hist" ]]; then
      track_violation "$ENV_NAME: password history_count $eff_hist < baseline $base_hist"
    fi

    # --- Required booleans (Auth0 format) ---
    bool_must_be_true "passwordPolicy.includeNumbers" '.passwordPolicy.includeNumbers'
    bool_must_be_true "passwordPolicy.includeSymbols" '.passwordPolicy.includeSymbols'
    bool_must_be_true "passwordPolicy.includeUppercase" '.passwordPolicy.includeUppercase'
    bool_must_be_true "passwordPolicy.includeLowercase" '.passwordPolicy.includeLowercase'
    bool_must_be_true "tenant.breach_detection_enabled" '.tenant.breach_detection_enabled'
    bool_must_be_true "guardianMfaPolicy.enabled" '.guardianMfaPolicy.enabled'

    # --- Token lifetimes (Auth0 format - seconds) ---
    num_must_be_ge "passwordPolicy.length.min" '.passwordPolicy.length.min'
    num_must_be_ge "passwordPolicy.history" '.passwordPolicy.history'
    
    # Session timeouts (lower is stricter, so effective <= baseline)
    local base_session eff_session base_idle eff_idle
    base_session="$(timeout "$YQ_TIMEOUT_SECS" yq -r '.tenant.session_lifetime // ""' "$BASELINE")"
    eff_session="$(timeout "$YQ_TIMEOUT_SECS" yq -r '.tenant.session_lifetime // 99999'  "$EFF")"
    if [[ -n "$base_session" && "$base_session" != "null" && "$eff_session" -gt "$base_session" ]]; then
      track_violation "$ENV_NAME: session_lifetime $eff_session > baseline $base_session (should be stricter)"
    fi
    
    base_idle="$(timeout "$YQ_TIMEOUT_SECS" yq -r '.tenant.idle_session_lifetime // ""' "$BASELINE")"
    eff_idle="$(timeout "$YQ_TIMEOUT_SECS" yq -r '.tenant.idle_session_lifetime // 99999'  "$EFF")"
    if [[ -n "$base_idle" && "$base_idle" != "null" && "$eff_idle" -gt "$base_idle" ]]; then
      track_violation "$ENV_NAME: idle_session_lifetime $eff_idle > baseline $base_idle (should be stricter)"
    fi

    # --- Logout URLs must include required enterprise URLs (Auth0 format) ---
    if timeout "$YQ_TIMEOUT_SECS" yq -e '.tenant.allowed_logout_urls[]?' "$BASELINE" >/dev/null 2>&1; then
      mapfile -t REQUIRED_URLS < <(timeout "$YQ_TIMEOUT_SECS" yq -r '.tenant.allowed_logout_urls[]?' "$BASELINE" 2>/dev/null || true)
      for url in "${REQUIRED_URLS[@]}"; do
        [[ -z "$url" || "$url" == "null" ]] && continue
        if ! timeout "$YQ_TIMEOUT_SECS" yq -r '.tenant.allowed_logout_urls[]?' "$EFF" 2>/dev/null | grep -Fxq "$url"; then
          track_violation "$ENV_NAME: missing required logout URL $url"
        fi
      done
    fi

    # --- Rules enforcement (Auth0 format) ---
    if timeout "$YQ_TIMEOUT_SECS" yq -e '.rules[]?' "$BASELINE" >/dev/null 2>&1; then
      mapfile -t BASELINE_RULES < <(timeout "$YQ_TIMEOUT_SECS" yq -r '.rules[]? | .name' "$BASELINE" 2>/dev/null || true)
      for rule_name in "${BASELINE_RULES[@]}"; do
        [[ -z "$rule_name" || "$rule_name" == "null" ]] && continue
        if ! timeout "$YQ_TIMEOUT_SECS" yq -r '.rules[]? | select(.enabled == true) | .name' "$EFF" 2>/dev/null | grep -Fxq "$rule_name"; then
          track_violation "$ENV_NAME: missing required rule: $rule_name"
        fi
      done
    fi
  done

  return "$VIOLATION_COUNT"
}

main() {
  need_yq

  # Resolve globs ONCE to avoid yq seeing empty globs
  shopt -s nullglob
  BASE_FILES=( "$BASE_DIR"/*.yml )
  OVERLAY_FILES=( "$OVERLAY_DIR"/*.yml )
  shopt -u nullglob

  [[ ${#BASE_FILES[@]}    -gt 0 ]] || { echo -e "${RED}❌${NC} No YAML in $BASE_DIR"; exit 1; }
  [[ ${#OVERLAY_FILES[@]} -gt 0 ]] || { echo -e "${RED}❌${NC} No YAML in $OVERLAY_DIR"; exit 1; }

  for env in dev qa prod; do
    if [[ ! -f "$TENANTS_DIR/$env/$TENANT/config.yml" ]]; then
      echo -e "${RED}❌${NC} Missing $TENANTS_DIR/$env/$TENANT/config.yml" 1>&2
      exit 1
    fi
    render_env "$env"
  done

  cross_env_diffs

  echo
  echo -e "${BLUE}▶${NC} Enforcing shared-sec baseline"
  if ! enforce_shared_sec; then
    echo
    echo -e "${RED}❌ Enforcement failed: $VIOLATION_COUNT security violations found${NC}"
    
    if [[ "$CI_MODE" == "true" ]]; then
      echo "::group::Security Violations Summary"
      printf '%s\n' "${VIOLATIONS[@]}"
      echo "::endgroup::"
    fi
    
    exit 1
  fi
  echo -e "${GREEN}✅ Enforcement passed${NC}"
  
  if [[ "$CI_MODE" == "true" ]]; then
    echo "::notice title=Security Check Passed::All Auth0 configurations meet enterprise security baseline requirements"
  fi
}

main "$@"