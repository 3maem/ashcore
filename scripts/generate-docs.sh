#!/bin/bash
# ASH SDK Documentation Generator
# Generates API documentation for all SDK implementations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "ASH SDK Documentation Generator"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

# Create output directory
mkdir -p "$ROOT_DIR/docs/generated"

# ==========================================
# Rust Documentation (rustdoc)
# ==========================================
echo "Generating Rust documentation..."
if command -v cargo &> /dev/null; then
    cd "$ROOT_DIR"
    if cargo doc --no-deps --workspace 2>/dev/null; then
        success "Rust documentation generated: target/doc/"
        # Copy to docs/generated
        if [ -d "target/doc" ]; then
            cp -r target/doc docs/generated/rust
            success "Copied to docs/generated/rust/"
        fi
    else
        warning "Rust documentation generation failed (cargo doc)"
    fi
else
    warning "Rust not installed - skipping rustdoc"
fi
echo ""

# ==========================================
# Node.js Documentation (TypeDoc)
# ==========================================
echo "Generating Node.js documentation..."
if [ -d "$ROOT_DIR/packages/ash-node-sdk" ]; then
    cd "$ROOT_DIR/packages/ash-node-sdk"
    if command -v npm &> /dev/null; then
        # Install typedoc if not present
        if ! npm list typedoc &> /dev/null; then
            npm install --save-dev typedoc
        fi
        if npm run docs 2>/dev/null; then
            success "Node.js documentation generated: packages/ash-node-sdk/docs/"
            # Copy to docs/generated
            if [ -d "docs" ]; then
                cp -r docs "$ROOT_DIR/docs/generated/node"
                success "Copied to docs/generated/node/"
            fi
        else
            warning "Node.js documentation generation failed (typedoc)"
        fi
    else
        warning "npm not installed - skipping TypeDoc"
    fi
else
    warning "packages/ash-node-sdk not found - skipping"
fi
echo ""

# ==========================================
# Summary
# ==========================================
echo "=========================================="
echo "Documentation Generation Complete"
echo "=========================================="
echo ""
echo "Generated documentation locations:"
echo "  - Rust:    docs/generated/rust/ashcore/index.html"
echo "  - Node.js: docs/generated/node/index.html"
echo ""
echo "Or view source locations:"
echo "  - Rust:    target/doc/ashcore/index.html"
echo "  - Node.js: packages/ash-node-sdk/docs/index.html"
echo ""
echo "Installation commands for documentation tools:"
echo "  - Rust:    (included with rustup)"
echo "  - Node.js: npm install --save-dev typedoc"
