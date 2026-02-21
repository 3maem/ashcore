# ASH Unified Proof Example

This example demonstrates **unified proofs** — multi-step request chaining where each step's proof includes a hash of the previous step's proof.

## Scenario

A three-step checkout flow where an attacker cannot skip steps, replay earlier steps, or reorder the sequence.

1. **Add items** to cart (basic proof)
2. **Set shipping** address (chains to step 1 via `previousProof`)
3. **Submit payment** (chains to step 2, scoped on `amount` + `currency`)

## Quick Start

```bash
npm install
npm start
```

The server starts and runs a built-in demo that completes the full checkout flow.

## How It Works

### 1. Client chains requests with `previousProof`

```javascript
// Step 1: Basic proof (no chain)
const step1 = ashBuildRequest({ nonce, contextId, method, path, body });

// Step 2: Chain to step 1
const step2 = ashBuildRequest({
  nonce, contextId, method, path, body,
  previousProof: step1.proof,           // Links to step 1
});

// Step 3: Chain to step 2 + scope
const step3 = ashBuildRequest({
  nonce, contextId, method, path, body,
  previousProof: step2.proof,           // Links to step 2
  scope: ['amount', 'currency'],        // Only protect critical fields
});
```

### 2. Server verifies the chain

```javascript
const result = ashVerifyRequest({
  headers, method, path, body, nonce, contextId,
  previousProof,                        // Server tracks last proof per session
  scope: ['amount', 'currency'],        // Must match client scope
});
```

### 3. Attack resistance

| Attack | Result |
|--------|--------|
| Complete the flow normally | All proofs valid |
| Skip step 1, go to step 2 | **Fails** — no previous proof |
| Replay step 1 in step 3 | **Fails** — chain hash mismatch |
| Change `amount` in step 3 | **Fails** — scoped field tampered |
| Change `saveCard` in step 3 | Still valid (not in scope) |

## When to Use Unified Mode

- Multi-step workflows (checkout, wizards, approval chains)
- Sequential API calls where order matters
- Combining scoped protection with request chaining
- Preventing step-skipping and replay attacks across a flow

## Error Codes

| Code | Error | Description |
|------|-------|-------------|
| 450 | `ASH_CTX_NOT_FOUND` | Context doesn't exist |
| 451 | `ASH_CTX_EXPIRED` | Context has expired |
| 452 | `ASH_CTX_ALREADY_USED` | Replay attempt |
| 460 | `ASH_PROOF_INVALID` | Proof mismatch (tampering or chain break) |
