# ASH Security Architecture

This document explains the system-level security architecture of ASH and how its components interact to provide request integrity and replay protection.

For security best practices, see [security-checklist.md](security-checklist.md).

---

## High-Level Architecture

ASH operates as a request integrity library embedded in both client and server applications.

It validates that:

- Requests are authentic
- Requests were not modified
- Requests are not replayed
- Requests are bound to a specific endpoint

---

## Core Components

### Server Application (using ASH)

Responsible for:

- Context creation (nonce + contextId generation)
- Nonce generation (CSPRNG)
- Proof verification
- Replay detection
- TTL enforcement
- Endpoint binding validation
- Context consumption

### Client Application (using ASH)

Responsible for:

- Secret derivation (from server-provided nonce)
- Request hashing
- Proof generation (HMAC-SHA256)
- Secure secret handling (destroy after use)

### Context Store

Responsible for:

- Single-use enforcement
- Atomic consumption
- TTL expiration

Available implementations:

| Store | Package | Use Case |
|-------|---------|----------|
| `AshMemoryStore` | `@3maem/ash-node-sdk` | Development and testing |
| `AshRedisStore` | `@3maem/ash-node-sdk` | Production (distributed) |

Custom stores can implement the `AshContextStore` interface.

---

## System Flow

```
1. Client requests a context from the server

2. Server generates nonce + contextId, stores context
   ┌──────────────────────┐
   │  Server Application  │
   │  (generates nonce)   │
   └──────────┬───────────┘
              ↓
   Returns { nonce, contextId, binding }

3. Client derives secret, builds proof, sends request
   ┌──────────────────────┐
   │  Client Application  │
   │  (derives + signs)   │
   └──────────┬───────────┘
              ↓
   POST with x-ash-* headers

4. Server re-derives secret, verifies proof, consumes context
   ┌──────────────────────┐
   │  Server Application  │
   │  (verify + consume)  │
   └──────────────────────┘
```

If tampered or replayed, verification fails.

---

## Security Guarantees

At the architecture level, ASH guarantees:

- Request integrity
- Single-use enforcement
- Replay prevention
- Endpoint binding

These guarantees hold only when TLS and proper server configuration are present.

---

## Trust Boundaries

Security assumptions change across:

1. Client to Internet
2. Internet to Server
3. Server to Context Store

All boundaries are treated as hostile environments.

---

## Security Responsibilities by Layer

| Layer | Responsibility |
|-------|----------------|
| TLS | Confidentiality |
| Authentication | Identity |
| Authorization | Permissions |
| ASH | Integrity + Replay protection |

ASH complements -- not replaces -- these controls.

---

## Deployment Patterns

### Recommended

- HTTPS only
- Redis with TLS for production context stores
- Short TTLs (default: 300 seconds)
- Rate limiting
- Synchronized clocks (NTP)

### Avoid

- In-memory stores in distributed/clustered deployments
- Long-lived contexts
- Unsynchronized distributed state

---

## Design Principles

ASH architecture follows:

- Minimal attack surface
- Stateful single-use context verification
- Single-use guarantees
- Deterministic canonicalization across platforms
- Defense-in-depth

---

## Available Packages

| Language | Package | Registry |
|----------|---------|----------|
| Rust | `ashcore` | crates.io |
| Node.js | `@3maem/ash-node-sdk` | npm |

---

## Summary

ASH provides integrity verification for HTTP requests between client and server applications.

It strengthens request security without interfering with existing authentication or authorization systems.
