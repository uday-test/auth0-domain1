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

# ---------- helpers ----------
need_yq() {
  if ! command -v yq >/dev/null 2>&1; then
    echo "❌ Missing 'yq'. Install v4+: https://github.com/mikefarah/yq#install" 1>&2
    exit 2
  fi
  local ver
  ver="$(yq --version 2>/dev/null || true)"
  if ! grep -Eq 'version v?4\.' <<<"$ver"; then
    echo "❌ yq v4+ required. Found: $ver" 1>&2
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

# ---------- rendering ----------
render_env() {
  local env="$1"
  local base_merged="$TMP_DIR/${env}.base.yml"
  local eff_merged="$OUT_DIR/$env/$TENANT.effective.yml"
  local diff_out="$OUT_DIR/$env/$TENANT.diff.txt"

  echo "▶ Rendering $env for tenant $TENANT"
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

main() {
  need_yq

  # Resolve globs ONCE to avoid yq seeing empty globs
  shopt -s nullglob
  BASE_FILES=( "$BASE_DIR"/*.yml )
  OVERLAY_FILES=( "$OVERLAY_DIR"/*.yml )
  shopt -u nullglob

  [[ ${#BASE_FILES[@]}    -gt 0 ]] || { echo "❌ No YAML in $BASE_DIR"; exit 1; }
  [[ ${#OVERLAY_FILES[@]} -gt 0 ]] || { echo "❌ No YAML in $OVERLAY_DIR"; exit 1; }

  for env in dev qa prod; do
    if [[ ! -f "$TENANTS_DIR/$env/$TENANT/config.yml" ]]; then
      echo "❌ Missing $TENANTS_DIR/$env/$TENANT/config.yml" 1>&2
      exit 1
    fi
    render_env "$env"
  done

  cross_env_diffs

  echo
  echo "✅ Configuration rendering complete"
  echo "Generated files:"
  echo "  • Effective configs: out/{env}/${TENANT}.effective.yml"
  echo "  • Change diffs: out/{env}/${TENANT}.diff.txt" 
  echo "  • Cross-env diffs: out/{env1}_vs_{env2}.${TENANT}.diff.txt"
  
  if [[ "$CI_MODE" == "true" ]]; then
    echo "::notice title=Config Rendering Complete::All configuration files generated successfully"
  fi
}

main "$@"