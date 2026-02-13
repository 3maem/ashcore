#!/usr/bin/env bash
# ASH Conformance Suite — Run all SDK runners
# Usage: ./scripts/test-conformance-all.sh
#
# Runs all 7 conformance runners (6 SDKs + WASM JS-in-Node).
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

# ── 3. Python ─────────────────────────────────────────────────
if command -v python &>/dev/null || command -v python3 &>/dev/null; then
  PYTEST=$(command -v pytest || command -v pytest3 || echo "")
  if [ -n "$PYTEST" ]; then
    run "Python (ash-python-sdk)" \
      "$PYTEST" "$ROOT/packages/ash-python-sdk/tests/test_conformance.py" -v
  else
    skip "Python (ash-python-sdk)" "pytest not found"
  fi
else
  skip "Python (ash-python-sdk)" "python not found"
fi

# ── 4. Go ─────────────────────────────────────────────────────
if command -v go &>/dev/null; then
  run "Go (ash-go-sdk)" \
    go test -v -run TestConformanceSuite "$ROOT/packages/ash-go-sdk"
else
  skip "Go (ash-go-sdk)" "go not found"
fi

# ── 5. PHP ────────────────────────────────────────────────────
if command -v php &>/dev/null && [ -d "$ROOT/packages/ash-php-sdk/vendor" ]; then
  run "PHP (ash-php-sdk)" \
    php "$ROOT/packages/ash-php-sdk/vendor/bin/phpunit" \
      --configuration "$ROOT/packages/ash-php-sdk/phpunit.xml" \
      --filter ConformanceSuiteTest
else
  skip "PHP (ash-php-sdk)" "php not found or vendor missing"
fi

# ── 6. WASM (Rust-native) ────────────────────────────────────
run "WASM Rust-native (ash-wasm-sdk)" \
  cargo test --manifest-path "$ROOT/packages/ash-wasm-sdk/Cargo.toml" --test conformance_suite

# ── 7. WASM (JS-in-Node) ─────────────────────────────────────
if command -v node &>/dev/null && [ -d "$ROOT/packages/ash-wasm-sdk/pkg" ]; then
  run "WASM JS-in-Node (ash-wasm-sdk)" \
    node "$ROOT/packages/ash-wasm-sdk/tests/conformance_wasm.mjs"
else
  skip "WASM JS-in-Node (ash-wasm-sdk)" "node not found or pkg not built (run wasm-pack build first)"
fi

# ── Summary ───────────────────────────────────────────────────
summary
exit 0
