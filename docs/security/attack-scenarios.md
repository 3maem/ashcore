# ASH Attack Scenarios & Defense Diagrams

This document visualizes common attack attempts and how ASH prevents them.

---

## 1. Request Tampering

### Attack

```
┌──────────────────────┐
│      Attacker        │
└──────────┬───────────┘
           ↓
   Intercepts request
           ↓
   Modifies body/params
           ↓
   Forwards to server
           ↓
┌──────────────────────┐
│       Server         │
└──────────────────────┘
```

### Result

❌ Proof mismatch → verification fails

### Defense

- HMAC proof
- Body hashing

---

## 2. Replay Attack

### Attack

```
┌──────────────────────┐
│      Attacker        │
└──────────┬───────────┘
           ↓
  Captures valid request
           ↓
     Resends later
           ↓
┌──────────────────────┐
│       Server         │
└──────────────────────┘
```

### Result

❌ Context already consumed → rejected

### Defense

- Single-use contexts
- TTL expiration

---

## 3. Endpoint Substitution

### Attack

```
┌──────────────────────┐
│      Attacker        │
└──────────┬───────────┘
           ↓
  Valid proof for /profile
           ↓
   Reused on /transfer
           ↓
┌──────────────────────┐
│       Server         │
└──────────────────────┘
```

### Result

❌ Binding mismatch → rejected

### Defense

- Method/path/query binding

---

## 4. Timing Attacks

### Attack

```
┌──────────────────────┐
│      Attacker        │
└──────────┬───────────┘
           ↓
  Measures comparison timing
           ↓
  Attempts to guess proof
           ↓
┌──────────────────────┐
│       Server         │
└──────────────────────┘
```

### Result

❌ No signal leakage

### Defense

- Constant-time comparisons

---

## 5. Memory Forensics

### Attack

```
┌──────────────────────┐
│      Attacker        │
└──────────┬───────────┘
           ↓
  Access process memory
           ↓
  Extract secrets
           ↓
┌──────────────────────┐
│    Server Memory     │
└──────────────────────┘
```

### Result

❌ Secrets cleared after use

### Defense

- Secure memory utilities

---

## Summary Table

| Attack | Prevented By |
|--------|--------------|
| Tampering | HMAC proof |
| Replay | Single-use contexts |
| Endpoint swap | Binding validation |
| Timing | Constant-time compare |
| Memory leaks | Secure clearing |
