# ASH Threat Model

**Version:** v1.0.0-beta
**Date:** 2026-02-14
**Classification:** Public

## 1. Overview

This document outlines the threat model for ASH (Application Security Hash). It identifies potential threats, attack vectors, and the security controls implemented to mitigate them.

### 1.1 Scope

- **In Scope:** `ashcore` Rust crate and `@3maem/ash-node-sdk` Node.js package
- **Out of Scope:** Application-specific implementations, network security, browser-side JavaScript

### 1.2 Target Environment

- Web applications using HTTP/HTTPS
- API servers and clients

---

## 2. Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| **Script Kiddie** | Automated tools, basic knowledge | Disruption, reputation |
| **Malicious User** | API access, request interception | Financial gain, data theft |
| **Network Attacker** (MITM) | Traffic interception, modification | Replay attacks, tampering |
| **Insider** | System access, valid credentials | Fraud, data exfiltration |
| **Advanced Persistent Threat** | Significant resources, 0-day exploits | Intellectual property, sabotage |

---

## 3. Assets

| Asset | Value | Protection Level |
|-------|-------|------------------|
| **Nonces** | High | Cryptographic random generation |
| **Client Secrets** | High | HMAC derivation, ephemeral |
| **Proofs** | High | Cryptographic integrity |
| **Context IDs** | Medium | One-time use, TTL enforced |
| **Payload Data** | High | Integrity verification |

---

## 4. Threats and Mitigations

### 4.1 Replay Attacks

**Threat:** Attacker intercepts a valid request and resends it later.

**Attack Vectors:**
- Network sniffing and replay
- Log file replay
- Browser cache exploitation

**Mitigations:**
- ✅ One-time context IDs (consumed on use)
- ✅ Timestamp validation (5-minute default TTL)
- ✅ Nonce uniqueness (128+ bits entropy)
- ✅ Clock skew tolerance (30 seconds)

**Residual Risk:** Low (requires real-time interception within TTL window)

---

### 4.2 Request Tampering

**Threat:** Attacker modifies request payload, endpoint, or headers.

**Attack Vectors:**
- MITM modification
- Proxy manipulation
- Client-side tampering

**Mitigations:**
- ✅ HMAC-SHA256 proof binding (payload + endpoint + timestamp)
- ✅ Canonicalization ensures deterministic serialization
- ✅ Endpoint binding prevents context reuse

**Residual Risk:** Very Low (cryptographically infeasible to forge)

---

### 4.3 Timing Attacks

**Threat:** Attacker measures response times to deduce secret information.

**Attack Vectors:**
- Proof comparison timing
- Error path timing
- Memory access timing

**Mitigations:**
- ✅ Constant-time comparison (`subtle` crate)
- ✅ Fixed iteration count (8 iterations, 2048 bytes)
- ✅ Uniform padding for all comparisons
- ✅ No early-exit in verification loops

**Residual Risk:** Negligible (constant-time operations)

---

### 4.4 Denial of Service (DoS)

**Threat:** Attacker exhausts server resources.

**Attack Vectors:**
- Oversized payloads
- Deeply nested JSON
- Excessive array indices
- Regex complexity (ReDoS)

**Mitigations:**
- ✅ Payload size limit (10 MB)
- ✅ JSON nesting depth limit (64 levels)
- ✅ Array index limit (10,000)
- ✅ Scope field limit (100 fields)
- ✅ Scope policy pattern limits (8 wildcards, 512-byte patterns)
- ✅ Nonce length limit (512 hex chars)

**Residual Risk:** Low (resource limits enforced)

---

### 4.5 Information Disclosure

**Threat:** Attacker gains sensitive information from error messages or logs.

**Attack Vectors:**
- Verbose error messages
- Stack traces in responses
- Timing side-channels

**Mitigations:**
- ✅ Sanitized error messages (no input echoing)
- ✅ Generic error messages for canonicalization failures
- ✅ No secret material in error responses
- ✅ Consistent error timing

**Residual Risk:** Low (safe error handling)

---

### 4.6 Weak Key Material

**Threat:** Attacker exploits weak or predictable nonces/secrets.

**Attack Vectors:**
- Insufficient entropy
- Predictable randomness
- Key reuse

**Mitigations:**
- ✅ Minimum 128 bits entropy (32 hex chars)
- ✅ CSPRNG via `getrandom` (OS entropy)
- ✅ Context-bound secrets (unique per context_id + binding)
- ✅ Hex format validation

**Residual Risk:** Very Low (cryptographic best practices)

---

### 4.7 Integer Overflow

**Threat:** Attacker exploits integer overflow for undefined behavior.

**Attack Vectors:**
- Timestamp manipulation
- Array index overflow
- Size calculation overflow

**Mitigations:**
- ✅ Saturating arithmetic for index calculations
- ✅ Timestamp bounds checking (max: year 3000)
- ✅ 64-bit timestamps prevent overflow

**Residual Risk:** Negligible (overflow-safe operations)

---

### 4.8 Memory Safety

**Threat:** Attacker exploits memory corruption vulnerabilities.

**Attack Vectors:**
- Buffer overflows
- Use-after-free
- Uninitialized memory

**Mitigations:**
- ✅ 100% Safe Rust (`#![forbid(unsafe_code)]`)
- ✅ Bounds checking on all array operations
- ✅ RAII memory management
- ✅ No `unsafe` blocks

**Residual Risk:** None (safe language guarantees)

---

## 5. Attack Scenarios

### Scenario 1: Replay Attack

```
Attacker intercepts: POST /api/transfer with valid proof
Attacker waits: 2 minutes
Attacker resends: Same request

Defense: 
- Context already consumed → ASH_CTX_ALREADY_USED (452)
- OR timestamp expired → ASH_CTX_EXPIRED (451)
```

### Scenario 2: Payload Modification

```
Attacker intercepts: {"amount": 100} with proof X
Attacker modifies: {"amount": 10000} with proof X

Defense:
- Proof verification fails → ASH_PROOF_INVALID (460)
- HMAC mismatch detected
```

### Scenario 3: Endpoint Confusion

```
Attacker gets proof for: POST /api/transfer
Attacker sends to: POST /api/refund

Defense:
- Binding mismatch → ASH_BINDING_MISMATCH (461)
```

---

## 6. Security Controls Summary

| Control | Implementation | Verification |
|---------|---------------|--------------|
| Cryptographic Proof | HMAC-SHA256 | Unit tests, 134 cross-SDK conformance vectors |
| Constant-Time Compare | Rust: `subtle` crate; Node.js: `crypto.timingSafeEqual` | Security audit, timing tests |
| Input Validation | Length/type limits | Property-based tests |
| Replay Prevention | Context consumption | Integration tests |
| Safe Memory (Rust) | `#![forbid(unsafe_code)]` + `zeroize` crate | Compiler guarantees |
| Safe Memory (Node.js) | Best-effort `destroy()` | Code review |
| Error Sanitization | Generic messages | Code review |

---

## 7. Limitations and Assumptions

### 7.1 Assumptions

1. **HTTPS Transport:** ASH does not encrypt data, only signs it
2. **Synchronized Clocks:** Client/server clocks within 5 minutes
3. **Secure Context Store:** Server-side context storage is secure
4. **CSPRNG Availability:** OS provides cryptographically secure randomness

### 7.2 Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| No encryption | Payload visible | Use HTTPS |
| No authentication | Anyone with valid proof accepted | Implement separate auth |
| Clock skew | Legitimate requests may fail | 30-second tolerance |
| Context storage required | Server state needed | Redis/memory stores |

---

## 8. Compliance Mapping

| Standard | Requirement | Status |
|----------|-------------|--------|
| OWASP ASVS | V2.10 (Cryptography) | ✅ Compliant |
| OWASP ASVS | V5.3 (Output Encoding) | ✅ Compliant |
| OWASP ASVS | V8.2 (Anti-tampering) | ✅ Compliant |
| NIST 800-63B | Authenticator Binding | ✅ Compliant |
| CWE Top 25 | CWE-307 (Brute Force) | ✅ Mitigated |
| CWE Top 25 | CWE-20 (Input Validation) | ✅ Mitigated |
| CWE Top 25 | CWE-798 (Hardcoded Credentials) | ✅ N/A |

---

## 9. Security Testing

### Rust (`ashcore` crate)

| Test Type | Coverage | Status |
|-----------|----------|--------|
| Unit Tests | 300+ tests | 100% pass |
| Integration Tests | 1,700+ tests | 100% pass |
| Fuzz Tests | 57 tests | 100% pass |
| Property-Based | 26 tests | 100% pass |
| Conformance Vectors | 134 vectors | 100% pass |

### Node.js (`@3maem/ash-node-sdk`)

| Test Type | Coverage | Status |
|-----------|----------|--------|
| Unit + Integration | 1,490+ tests | 100% pass |
| Security Audit Tests | Comprehensive | 100% pass |
| Conformance Vectors | 134 vectors | 100% pass |

---

## 10. Incident Response

### Detected Attack Indicators

| Indicator | Action |
|-----------|--------|
| High rate of ASH_CTX_ALREADY_USED | Potential replay attack - rate limit client |
| High rate of ASH_PROOF_INVALID | Potential tampering - investigate payload |
| High rate of ASH_TIMESTAMP_INVALID | Clock skew or replay - check NTP sync |
| High rate of ASH_BINDING_MISMATCH | Context confusion - verify client implementation |

### Response Procedures

1. **Log Analysis:** Check ASH error codes in application logs
2. **Rate Limiting:** Implement per-client rate limits
3. **Alerting:** Configure monitoring for error code spikes
4. **Forensics:** Preserve context IDs for investigation

---

## 11. References

- [ASH Security Guide](./security-checklist.md)
- [ASH Attack Scenarios](./attack-scenarios.md)
- [ASH Architecture](./architecture.md)
- [Error Codes Reference](../reference/error-codes.md)

---

**Document Owner:** Security Team
**Review Cycle:** Quarterly
**Last Review:** 2026-02-14

---

*This threat model is a living document. Update it when new threats are identified or security controls change.*
