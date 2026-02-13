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
# Python Documentation (Sphinx)
# ==========================================
echo "Generating Python documentation..."
if [ -d "$ROOT_DIR/packages/ash-python-sdk" ]; then
    cd "$ROOT_DIR/packages/ash-python-sdk"
    if command -v sphinx-build &> /dev/null; then
        if sphinx-build -b html docs/source docs/_build 2>/dev/null; then
            success "Python documentation generated: packages/ash-python-sdk/docs/_build/"
            # Copy to docs/generated
            if [ -d "docs/_build" ]; then
                cp -r docs/_build "$ROOT_DIR/docs/generated/python"
                success "Copied to docs/generated/python/"
            fi
        else
            warning "Python documentation generation failed (sphinx-build)"
        fi
    else
        warning "Sphinx not installed - skipping"
        echo "  Install with: pip install sphinx sphinx-rtd-theme"
    fi
else
    warning "packages/ash-python-sdk not found - skipping"
fi
echo ""

# ==========================================
# Go Documentation (godoc/pkgsite)
# ==========================================
echo "Generating Go documentation..."
if [ -d "$ROOT_DIR/packages/ash-go-sdk" ]; then
    cd "$ROOT_DIR/packages/ash-go-sdk"
    if command -v go &> /dev/null; then
        # Generate documentation using go doc
        mkdir -p "$ROOT_DIR/docs/generated/go"

        # Create HTML documentation using gomarkdoc if available
        if command -v gomarkdoc &> /dev/null; then
            gomarkdoc --output "$ROOT_DIR/docs/generated/go/index.md" . 2>/dev/null && \
                success "Go documentation generated: docs/generated/go/index.md"
        else
            # Fallback: generate text documentation
            go doc -all . > "$ROOT_DIR/docs/generated/go/api.txt" 2>/dev/null && \
                success "Go documentation generated: docs/generated/go/api.txt"
            echo "  For HTML docs, install gomarkdoc: go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest"
        fi

        echo "  View online: pkg.go.dev/github.com/3maem/ash-go-sdk"
    else
        warning "Go not installed - skipping"
    fi
else
    warning "packages/ash-go-sdk not found - skipping"
fi
echo ""

# ==========================================
# PHP Documentation (phpDocumentor)
# ==========================================
echo "Generating PHP documentation..."
if [ -d "$ROOT_DIR/packages/ash-php-sdk" ]; then
    cd "$ROOT_DIR/packages/ash-php-sdk"
    if command -v composer &> /dev/null; then
        # Check if phpDocumentor is installed
        if [ -f "vendor/bin/phpdoc" ]; then
            if vendor/bin/phpdoc 2>/dev/null; then
                success "PHP documentation generated: packages/ash-php-sdk/docs/api/"
                # Copy to docs/generated
                if [ -d "docs/api" ]; then
                    cp -r docs/api "$ROOT_DIR/docs/generated/php"
                    success "Copied to docs/generated/php/"
                fi
            else
                warning "PHP documentation generation failed (phpDocumentor)"
            fi
        elif command -v phpdoc &> /dev/null; then
            if phpdoc 2>/dev/null; then
                success "PHP documentation generated: packages/ash-php-sdk/docs/api/"
                if [ -d "docs/api" ]; then
                    cp -r docs/api "$ROOT_DIR/docs/generated/php"
                    success "Copied to docs/generated/php/"
                fi
            else
                warning "PHP documentation generation failed (phpDocumentor)"
            fi
        else
            warning "phpDocumentor not installed"
            echo "  Install with: composer require --dev phpdocumentor/phpdocumentor"
        fi
    else
        warning "Composer not installed - skipping PHP docs"
    fi
else
    warning "packages/ash-php-sdk not found - skipping"
fi
echo ""

# ==========================================
# WASM Documentation
# ==========================================
echo "Generating WASM documentation..."
if [ -d "$ROOT_DIR/packages/ash-wasm-sdk" ]; then
    cd "$ROOT_DIR/packages/ash-wasm-sdk"
    if command -v cargo &> /dev/null; then
        if cargo doc --no-deps 2>/dev/null; then
            success "WASM documentation generated"
            if [ -d "target/doc" ]; then
                cp -r target/doc "$ROOT_DIR/docs/generated/wasm"
                success "Copied to docs/generated/wasm/"
            fi
        else
            warning "WASM documentation generation failed"
        fi
    else
        warning "Rust not installed - skipping WASM docs"
    fi
else
    warning "packages/ash-wasm-sdk not found - skipping"
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
echo "  - Python:  docs/generated/python/index.html"
echo "  - Go:      docs/generated/go/ (or pkg.go.dev)"
echo "  - PHP:     docs/generated/php/index.html"
echo "  - WASM:    docs/generated/wasm/index.html"
echo ""
echo "Or view source locations:"
echo "  - Rust:    target/doc/ashcore/index.html"
echo "  - Node.js: packages/ash-node-sdk/docs/index.html"
echo "  - Python:  packages/ash-python-sdk/docs/_build/index.html"
echo "  - Go:      pkg.go.dev/github.com/3maem/ash-go-sdk"
echo "  - PHP:     packages/ash-php-sdk/docs/api/index.html"
echo "  - WASM:    packages/ash-wasm-sdk/target/doc/index.html"
echo ""
echo "Installation commands for documentation tools:"
echo "  - Rust:    (included with rustup)"
echo "  - Node.js: npm install --save-dev typedoc"
echo "  - Python:  pip install sphinx sphinx-rtd-theme"
echo "  - Go:      go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest"
echo "  - PHP:     composer require --dev phpdocumentor/phpdocumentor"
echo "  - WASM:    (uses rustdoc via cargo doc)"
