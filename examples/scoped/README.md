# ASH Scoped Proof Example

This example demonstrates **scoped proofs** — field-level integrity protection where only specified fields are covered by the proof.

## Scenario

An e-commerce order contains many fields, but only `amount` and `currency` are critical. If an attacker tampers with those fields, the proof fails. Changing `notes` or `preferences` has no effect on verification.

## Quick Start

```bash
npm install
npm start
```

The server starts and runs a built-in demo that creates an order with a scoped proof.

## How It Works

### 1. Client builds a scoped proof

```javascript
const result = ashBuildRequest({
  nonce,
  contextId,
  method: 'POST',
  path: '/api/orders',
  body,
  scope: ['amount', 'currency'], // Only these fields are in the proof
});
```

### 2. Server verifies with the same scope

```javascript
const result = ashVerifyRequest({
  headers: req.headers,
  method: 'POST',
  path: '/api/orders',
  body: JSON.stringify(req.body),
  nonce: ctx.nonce,
  contextId: ctx.id,
  scope: ['amount', 'currency'], // Must match client scope
});
```

### 3. Tamper resistance

| Action | Result |
|--------|--------|
| Send order as-is | Proof valid |
| Change `notes` | Proof still valid (not in scope) |
| Change `amount` | **Proof fails** |
| Change `currency` | **Proof fails** |

## When to Use Scoped Mode

- Large payloads where only a few fields are security-critical
- Forms with optional/cosmetic fields alongside financial data
- APIs where middleware may modify non-critical fields in transit

## Error Codes

| Code | Error | Description |
|------|-------|-------------|
| 450 | `ASH_CTX_NOT_FOUND` | Context doesn't exist |
| 451 | `ASH_CTX_EXPIRED` | Context has expired |
| 452 | `ASH_CTX_ALREADY_USED` | Replay attempt |
| 460 | `ASH_PROOF_INVALID` | Scoped proof mismatch (tampering detected) |
