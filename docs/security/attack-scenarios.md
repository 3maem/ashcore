# ASH Attack Scenarios & Defense Diagrams

This document visualizes common attack attempts and how ASH prevents them.

---

## 1. Request Tampering

### Attack

```
Attacker intercepts request
  -> Modifies body/params
  -> Forwards to server
```

### Result

Rejected -- proof mismatch, verification fails.

### Defense

- HMAC-SHA256 proof covers timestamp + binding + body hash
- SHA-256 body hash independently verified

---

## 2. Replay Attack

### Attack

```
Attacker captures valid request
  -> Waits
  -> Resends identical request
```

### Result

Rejected -- context already consumed, or timestamp expired.

### Defense

- Single-use contexts (consumed on verification)
- TTL expiration (default: 300 seconds)
- Timestamp freshness validation

---

## 3. Endpoint Substitution

### Attack

```
Attacker obtains valid proof for POST /api/profile
  -> Reuses proof on POST /api/transfer
```

### Result

Rejected -- binding mismatch.

### Defense

- Proof is bound to METHOD|PATH|QUERY
- Binding is part of the HMAC input

---

## 4. Timing Attacks

### Attack

```
Attacker sends many proof attempts
  -> Measures response timing
  -> Attempts to deduce correct proof bytes
```

### Result

Rejected -- no timing signal leakage.

### Defense

- Rust: constant-time comparison via `subtle` crate (fixed 2048-byte work size, 8 iterations)
- Node.js: `crypto.timingSafeEqual` with length padding
- No early-exit in verification loops

---

## 5. Memory Forensics

### Attack

```
Attacker gains access to process memory
  -> Attempts to extract secrets/proofs
```

### Result

Mitigated -- secrets cleared after use.

### Defense

- Rust: cryptographic zeroization via `zeroize` crate (Drop implementations on all sensitive fields)
- Node.js: best-effort cleanup via `destroy()` (dereferences sensitive values; JavaScript/V8 does not guarantee cryptographic zeroization due to garbage collection)

---

## Summary Table

| Attack | Defense |
|--------|---------|
| Tampering | HMAC-SHA256 proof + SHA-256 body hash |
| Replay | Single-use contexts + TTL + timestamp freshness |
| Endpoint swap | Binding validation (METHOD\|PATH\|QUERY) |
| Timing | Constant-time comparison |
| Memory forensics | Rust: `zeroize` crate; Node.js: best-effort `destroy()` |
