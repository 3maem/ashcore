<p align="center">
  <img src="assets/logo.png" alt="ASH Logo" width="600">
</p>

# ASH — Application Security Hash

**Version:** v1.0.0-beta | **License:** Apache-2.0 | **Conformance:** [134/134 vectors (byte-identical)](#conformance-status)

> **⚠️ Beta Notice:** This is v1.0.0-beta. Feature-complete but may undergo internal refinements. Not recommended for production-critical environments yet.

Request integrity and replay protection for modern applications.

ASH ensures that every request is:

- Authentic
- Unmodified
- Single-use
- Bound to its endpoint

---

## Why ASH?

HTTPS protects transport.
Authentication verifies identity.
Authorization controls access.

But requests themselves can still be replayed or reused.

ASH adds a dedicated integrity layer.

---

## How It Works

```
Client → Sign → Send → Verify → Consume
```

Each request includes a cryptographic proof that becomes invalid after use.

---

## What ASH is NOT

ASH is not authentication.
ASH is not authorization.
ASH is not a firewall.

It is an additional security layer.

---

## Available SDKs

| Language | Package | Install | License |
|----------|---------|---------|---------|
| **Rust** | `ashcore` | `cargo add ashcore` | Apache-2.0 |
| **Node.js** | `@3maem/ash-node-sdk` | `npm install @3maem/ash-node-sdk` | Apache-2.0 |

### Node.js SDK Highlights

- **Zero runtime dependencies** — uses only Node.js built-in `crypto`
- **1370+ tests** — conformance, PT, security audit, QA, fuzz, property-based
- **Three proof modes** — basic, scoped (field-level), unified (scoped + request chaining)
- **Express middleware** — `ashExpressMiddleware()` drop-in server verification
- **Fastify plugin** — `ashFastifyPlugin()` async plugin with request decoration
- **Context stores** — `AshMemoryStore` (in-memory) + `AshRedisStore` (production)
- **Scope policy registry** — route-level field enforcement (exact, param, wildcard)
- **CLI tool** — `ash build`, `ash verify`, `ash hash`, `ash inspect` from the terminal
- **Debug trace** — step-by-step pipeline inspection with timing
- **CJS + ESM + DTS** — dual build with full TypeScript declarations

---

## Examples

| Framework | Language | Directory |
|-----------|----------|-----------|
| Express | Node.js | [`examples/express/`](examples/express/) |
| Node Express | Node.js | [`examples/node-express/`](examples/node-express/) |
| Actix | Rust | [`examples/actix/`](examples/actix/) |

Node.js SDK also includes built-in examples at [`packages/ash-node-sdk/examples/`](packages/ash-node-sdk/examples/).

---

## Conformance Status

**All active SDKs pass 134/134 vectors (byte-identical).**
Vectors are locked. Any behavior change requires version bump + regenerated vectors.

All SDKs are tested against a single authoritative set of [134 conformance vectors](tests/conformance/vectors.json) generated from the Rust reference implementation.

| SDK | Status | Runner |
|-----|--------|--------|
| **Rust** | 134/134 | [`packages/ashcore/tests/conformance_suite.rs`](packages/ashcore/tests/conformance_suite.rs) |
| **Node.js** | 134/134 | [`packages/ash-node-sdk/tests/conformance.test.ts`](packages/ash-node-sdk/tests/conformance.test.ts) |

See [`tests/conformance/README.md`](tests/conformance/README.md) for vector format and determinism rules.

---

## Documentation

- [Security Guide](docs/security/security-checklist.md)
- [Security Whitepaper](docs/security/whitepaper.md)
- [Architecture](docs/security/architecture.md)
- [Attack Scenarios](docs/security/attack-scenarios.md)
- [Threat Model](docs/security/threat-model.md)
- [Error Codes](docs/reference/error-codes.md)
- [API Reference — Node.js](docs/reference/api-node.md)
- [API Reference — Rust](docs/reference/api-rust.md)
- [Middleware Reference](docs/reference/middleware.md)
- [Conformance Governance](docs/conformance-governance.md)
- [Troubleshooting](docs/troubleshooting.md)

---

## License

Apache-2.0

See [LICENSE](LICENSE) for full terms.

---

**Developed by 3maem | عمائم**
