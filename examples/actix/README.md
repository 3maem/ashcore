# ASH Actix-web (Rust) Integration Example

This example demonstrates how to integrate ASH with Actix-web for request integrity verification.

## Quick Start

```bash
# Create project
cargo new ash-actix-example
cd ash-actix-example

# Add dependencies to Cargo.toml
[dependencies]
actix-web = "4"
ashcore = "2.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = "0.4"

# Run
cargo run
```

## Setup

### 1. Create Store

```rust
use std::collections::HashMap;
use std::sync::Mutex;

struct AshStore {
    contexts: Mutex<HashMap<String, StoredContext>>,
}
```

### 2. Implement Verification

```rust
fn verify_ash(req: &HttpRequest, store: &AshStore, body: &str) -> Result<(), HttpResponse> {
    let context_id = req.headers().get("X-ASH-Context-ID")...;
    let timestamp = req.headers().get("X-ASH-Timestamp")...;
    let proof = req.headers().get("X-ASH-Proof")...;

    // Verify stored context
    let stored = store.get(context_id)?;

    // Check expiration
    if now > stored.expires_at { return Err(...); }

    // Verify proof
    let expected = ash_build_proof(...);
    if !timing_safe_equal(proof, &expected) { return Err(...); }

    // Consume
    store.consume(context_id)?;
    Ok(())
}
```

### 3. Register Routes

```rust
App::new()
    .app_data(store.clone())
    .route("/api/context", web::post().to(issue_context))
    .route("/api/transfer", web::post().to(transfer))
```

## Client Usage (Rust)

```rust
use ashcore::{ash_normalize_binding, ash_build_proof, ash_hash_body};
use reqwest::Client;

async fn make_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    // 1. Get context
    let ctx: ContextResponse = client
        .post("http://localhost:8080/api/context")
        .json(&serde_json::json!({"endpoint": "/api/transfer"}))
        .send()
        .await?
        .json()
        .await?;

    // 2. Build proof
    let payload = r#"{"from_account":"ACC_001","to_account":"ACC_002","amount":100}"#;
    let binding = ash_normalize_binding("POST", "/api/transfer", "")?;
    let body_hash = ash_hash_body(payload);
    let timestamp = current_time_ms().to_string();
    let proof = ash_build_proof(&ctx.client_secret, &timestamp, &binding, &body_hash);

    // 3. Make request
    let response = client
        .post("http://localhost:8080/api/transfer")
        .header("X-ASH-Context-ID", &ctx.context_id)
        .header("X-ASH-Timestamp", &timestamp)
        .header("X-ASH-Proof", &proof)
        .body(payload)
        .send()
        .await?;

    Ok(())
}
```

## Production Considerations

1. **Use Redis Store**: Implement async Redis-backed store
2. **Add Middleware**: Create proper Actix middleware for cleaner code
3. **Enable TLS**: Use rustls or native-tls
4. **Add Metrics**: Use actix-web-prometheus for monitoring

## Error Codes

| Code | Description |
|------|-------------|
| ASH_HEADERS_MISSING | Required headers not present |
| ASH_CTX_NOT_FOUND | Context doesn't exist |
| ASH_CTX_EXPIRED | Context has expired |
| ASH_CTX_USED | Context already consumed |
| ASH_PROOF_MISMATCH | Invalid proof |
