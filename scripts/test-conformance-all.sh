#!/usr/bin/env bash
# ASH Conformance Suite — Run all SDK runners
# Usage: ./scripts/test-conformance-all.sh
#
# Runs conformance runners for Rust core and Node.js SDK.
# Exits on first failure. Returns 0 only if all runners pass.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0
SKIP=0
RESULTS=()

run() {
  local name="$1"
  shift
  echo ""
  echo "════════════════════════════════════════════════════════════"
  echo "  $name"
  echo "════════════════════════════════════════════════════════════"
  if "$@"; then
    RESULTS+=("  PASS  $name")
    PASS=$((PASS + 1))
  else
    RESULTS+=("  FAIL  $name")
    FAIL=$((FAIL + 1))
    echo ""
    echo "FAILED: $name"
    echo "Stopping."
    summary
    exit 1
  fi
}

skip() {
  local name="$1"
  local reason="$2"
  RESULTS+=("  SKIP  $name ($reason)")
  SKIP=$((SKIP + 1))
  echo ""
  echo "  SKIP  $name — $reason"
}

summary() {
  echo ""
  echo "════════════════════════════════════════════════════════════"
  echo "  SUMMARY"
  echo "════════════════════════════════════════════════════════════"
  for r in "${RESULTS[@]}"; do
    echo "$r"
  done
  echo ""
  echo "  Pass: $PASS  Fail: $FAIL  Skip: $SKIP"
  echo "════════════════════════════════════════════════════════════"
}

# ── 1. Rust Core ──────────────────────────────────────────────
run "Rust Core (ashcore)" \
  cargo test --manifest-path "$ROOT/packages/ashcore/Cargo.toml" --test conformance_suite

# ── 2. Node.js ────────────────────────────────────────────────
if command -v node &>/dev/null && [ -d "$ROOT/packages/ash-node-sdk/node_modules" ]; then
  run "Node.js (ash-node-sdk)" \
    npx --prefix "$ROOT/packages/ash-node-sdk" vitest run --reporter=verbose
else
  skip "Node.js (ash-node-sdk)" "node not found or node_modules missing"
fi

# ── Summary ───────────────────────────────────────────────────
summary
exit 0
