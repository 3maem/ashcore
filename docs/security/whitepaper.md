# ashcore — Security Whitepaper

**Version:** 1.0
**Date:** 2026
**Author:** 3maem Co.

---

## Executive Summary

ASH (Application Security Hash) is a request integrity protocol designed to protect applications from tampering, replay attacks, and data manipulation.

It provides an additional protection layer that complements authentication, authorization, and transport security.

ASH focuses exclusively on **request integrity**.

---

## Problem Statement

Modern applications face significant security risks:

- **Request tampering** — Attackers modify data in transit
- **Replay attacks** — Valid requests are captured and resent
- **Endpoint substitution** — Proofs reused on different endpoints
- **Automated abuse** — Bots and scripts bypass controls
- **Client-side manipulation** — Parameters altered before submission

Traditional controls (authentication, authorization, TLS) do not guarantee request integrity at the application layer.

---

## Solution Overview

ASH introduces a cryptographic integrity protocol:

- **Cryptographic request proofs** — HMAC-based verification
- **Single-use contexts** — Each request validated only once
- **Short-lived tokens** — TTL-enforced expiration
- **Endpoint binding** — Proofs locked to method/path/query
- **Replay prevention** — Contexts consumed on verification

Each request becomes **verifiable** and **non-reusable**.

---

## Security Model

### ASH Enforces

- Request authenticity verification
- Request integrity validation
- Replay prevention
- Endpoint binding

### ASH Does NOT Replace

- Authentication (identity verification)
- Authorization (permission checks)
- TLS (transport encryption)

**Security remains layered. ASH is one layer.**

---

## Architecture

```
┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐    ┌─────────┐    ┌─────────┐
│ Client │ → │  Sign  │ → │  Send  │ → │ Verify │ → │ Consume │ → │ Destroy │
└────────┘    └────────┘    └────────┘    └────────┘    └─────────┘    └─────────┘
```

### Protocol Flow

1. **Server** creates a context (nonce, contextId, binding, clientSecret) and stores it
2. **Server** sends the nonce and contextId to the client
3. **Client** derives a client secret and builds an HMAC-SHA256 proof
4. **Client** sends the request with ASH headers (proof, timestamp, nonce, body hash, context ID)
5. **Server** consumes the context (atomic, one-time-use), re-derives the proof, and verifies
6. **Server** rejects if the proof doesn't match, context is expired, or already consumed

### Core Components

| Component | Responsibility |
|-----------|----------------|
| **Server** | Context creation, nonce generation, proof verification, replay detection |
| **Client** | Secret derivation, proof signing, header attachment |
| **Context Store** | Single-use enforcement, TTL expiration, atomic operations |

---

## Proof Modes

ASH supports three proof modes:

| Mode | Description |
|------|-------------|
| **Basic** | HMAC-SHA256 proof over timestamp + binding + body hash |
| **Scoped** | Basic proof + field-level scope hash for selective field protection |
| **Unified** | Scoped proof + chain hash linking to a previous proof for request chaining |

---

## Cryptographic Design

| Feature | Algorithm | Purpose |
|---------|-----------|---------|
| **Proof Generation** | HMAC-SHA256 | Request authentication |
| **Body Hashing** | SHA-256 | Integrity verification |
| **Nonce Generation** | CSPRNG | Unpredictability |
| **Key Derivation** | HMAC-based KDF | Secret derivation |
| **Comparison** | Constant-time | Timing attack prevention |

### Design Principles

- No custom cryptography
- Industry-standard primitives only
- Deterministic verification
- Minimal attack surface

---

## Threat Model

### Protected Threats

| Threat | Defense Mechanism |
|--------|-------------------|
| Tampering | HMAC proof verification |
| Replay | Single-use context consumption |
| Endpoint substitution | Binding validation |
| Parameter manipulation | Body hash verification |
| Timing attacks | Constant-time comparison |

### Out of Scope

- Compromised client devices
- Stolen credentials
- Server-side compromise
- Insider threats

---

## Defense-in-Depth

ASH implements multiple security layers:

- **Constant-time comparisons** — Prevents timing side-channels
- **Secure memory clearing** — Reduces forensic exposure
- **TTL enforcement** — Limits attack window
- **Atomic store operations** — Guarantees single-use

---

## Available Implementations

| Language | Package | Conformance |
|----------|---------|-------------|
| **Rust** | `ashcore` | 134/134 vectors |
| **Node.js** | `@3maem/ash-node-sdk` | 134/134 vectors |

All implementations are tested against a single authoritative set of conformance vectors generated from the Rust reference implementation.

---

## Deployment Best Practices

| Practice | Recommendation |
|----------|----------------|
| Transport | HTTPS only |
| TTL | 30 seconds (recommended) |
| Storage | Redis with TLS (production) |
| Secrets | Rotate regularly |
| Monitoring | Enable logging |
| Clocks | Keep synchronized |

---

## Limitations

ASH is **not** a complete security solution.

It must be combined with:

- Strong authentication
- Proper authorization
- Secure infrastructure
- Input validation
- Rate limiting

ASH strengthens — but does not replace — these controls.

---

## Conclusion

ASH provides a **lightweight**, **developer-friendly**, and **enterprise-ready** protocol for request integrity.

### Key Takeaways

1. **Protocol, not a framework** — ASH defines a wire-level request integrity protocol with conformance vectors
2. **Additional layer** — ASH complements existing security controls
3. **Not a replacement** — Authentication, authorization, and TLS remain essential
4. **Shared responsibility** — Security requires proper configuration and infrastructure

ASH strengthens request integrity through cryptographic verification and single-use enforcement.

**Security is a shared responsibility. ASH is one layer.**

---

## Contact

For security inquiries:

**Email:** security@ashcore.com

---

© 2026 3maem Co. All rights reserved.
