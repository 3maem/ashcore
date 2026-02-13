/*
ASH Integration Example: Actix-web (Rust) Server

This example demonstrates how to integrate ASH with Actix-web
for request integrity verification and anti-replay protection.
*/

use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, middleware};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ashcore::{
    ash_normalize_binding,
    ash_derive_client_secret,
    ash_build_proof,
    ash_hash_body,
    ash_timing_safe_equal,
};

// Stored context
#[derive(Clone)]
struct StoredContext {
    context_id: String,
    nonce: String,
    binding: String,
    expires_at: u64,
    consumed: bool,
}

// In-memory store (use Redis in production)
struct AshStore {
    contexts: Mutex<HashMap<String, StoredContext>>,
}

impl AshStore {
    fn new() -> Self {
        Self {
            contexts: Mutex::new(HashMap::new()),
        }
    }

    fn create(&self, binding: &str, ttl_ms: u64) -> StoredContext {
        let now = current_time_ms();
        let context_id = format!("ash_{}", generate_nonce());
        let nonce = generate_nonce();

        let ctx = StoredContext {
            context_id: context_id.clone(),
            nonce,
            binding: binding.to_string(),
            expires_at: now + ttl_ms,
            consumed: false,
        };

        self.contexts.lock().unwrap().insert(context_id, ctx.clone());
        ctx
    }

    fn get(&self, context_id: &str) -> Option<StoredContext> {
        self.contexts.lock().unwrap().get(context_id).cloned()
    }

    fn consume(&self, context_id: &str) -> Result<(), &'static str> {
        let mut contexts = self.contexts.lock().unwrap();
        if let Some(ctx) = contexts.get_mut(context_id) {
            if ctx.consumed {
                return Err("already_consumed");
            }
            ctx.consumed = true;
            Ok(())
        } else {
            Err("not_found")
        }
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

// Request/Response types
#[derive(Deserialize)]
struct ContextRequest {
    endpoint: Option<String>,
    ttl_ms: Option<u64>,
}

#[derive(Serialize)]
struct ContextResponse {
    context_id: String,
    client_secret: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct TransferRequest {
    from_account: String,
    to_account: String,
    amount: f64,
}

#[derive(Deserialize)]
struct PaymentRequest {
    merchant_id: String,
    amount: f64,
    currency: Option<String>,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
    message: Option<String>,
    transaction_id: Option<String>,
    payment_id: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: Option<String>,
}

// Handlers
async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn issue_context(
    store: web::Data<AshStore>,
    body: web::Json<ContextRequest>,
) -> HttpResponse {
    let endpoint = body.endpoint.as_deref().unwrap_or("/api/transfer");
    let ttl_ms = body.ttl_ms.unwrap_or(30000);

    let binding = ash_normalize_binding("POST", endpoint, "").unwrap();
    let ctx = store.create(&binding, ttl_ms);

    let client_secret = ash_derive_client_secret(&ctx.nonce, &ctx.context_id, &binding).unwrap();

    HttpResponse::Ok().json(ContextResponse {
        context_id: ctx.context_id,
        client_secret,
        expires_at: ctx.expires_at,
    })
}

async fn transfer(
    req: HttpRequest,
    store: web::Data<AshStore>,
    body: web::Json<TransferRequest>,
) -> HttpResponse {
    // Verify ASH (simplified - use middleware in production)
    if let Err(resp) = verify_ash(&req, &store, &serde_json::to_string(&body.0).unwrap()) {
        return resp;
    }

    println!(
        "Transfer: {} from {} to {}",
        body.amount, body.from_account, body.to_account
    );

    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        message: Some("Transfer completed".to_string()),
        transaction_id: Some(format!("TXN_{}", current_time_ms())),
        payment_id: None,
    })
}

async fn payment(
    req: HttpRequest,
    store: web::Data<AshStore>,
    body: web::Json<PaymentRequest>,
) -> HttpResponse {
    if let Err(resp) = verify_ash(&req, &store, &serde_json::to_string(&body.0).unwrap()) {
        return resp;
    }

    let currency = body.currency.as_deref().unwrap_or("USD");
    println!(
        "Payment: {} {} to merchant {}",
        body.amount, currency, body.merchant_id
    );

    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        message: None,
        transaction_id: None,
        payment_id: Some(format!("PAY_{}", current_time_ms())),
    })
}

fn verify_ash(req: &HttpRequest, store: &AshStore, body: &str) -> Result<(), HttpResponse> {
    let context_id = req
        .headers()
        .get("X-ASH-Context-ID")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Forbidden().json(ErrorResponse {
                error: "Missing context ID".to_string(),
                code: Some("ASH_HEADERS_MISSING".to_string()),
            })
        })?;

    let timestamp = req
        .headers()
        .get("X-ASH-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Forbidden().json(ErrorResponse {
                error: "Missing timestamp".to_string(),
                code: Some("ASH_HEADERS_MISSING".to_string()),
            })
        })?;

    let proof = req
        .headers()
        .get("X-ASH-Proof")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Forbidden().json(ErrorResponse {
                error: "Missing proof".to_string(),
                code: Some("ASH_HEADERS_MISSING".to_string()),
            })
        })?;

    let stored = store.get(context_id).ok_or_else(|| {
        HttpResponse::Forbidden().json(ErrorResponse {
            error: "Context not found".to_string(),
            code: Some("ASH_CTX_NOT_FOUND".to_string()),
        })
    })?;

    let now = current_time_ms();
    if now > stored.expires_at {
        return Err(HttpResponse::Forbidden().json(ErrorResponse {
            error: "Context expired".to_string(),
            code: Some("ASH_CTX_EXPIRED".to_string()),
        }));
    }

    let binding = ash_normalize_binding(req.method().as_str(), req.path(), req.query_string()).unwrap();
    let body_hash = ash_hash_body(body);
    let client_secret = ash_derive_client_secret(&stored.nonce, context_id, &binding).unwrap();
    let expected_proof = ash_build_proof(&client_secret, timestamp, &binding, &body_hash).unwrap();

    if !ash_timing_safe_equal(proof.as_bytes(), expected_proof.as_bytes()) {
        return Err(HttpResponse::Forbidden().json(ErrorResponse {
            error: "Invalid proof".to_string(),
            code: Some("ASH_PROOF_MISMATCH".to_string()),
        }));
    }

    store.consume(context_id).map_err(|_| {
        HttpResponse::Forbidden().json(ErrorResponse {
            error: "Context already used".to_string(),
            code: Some("ASH_CTX_USED".to_string()),
        })
    })?;

    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("ASH Actix-web example running on port 8080");
    println!("Protected endpoints: /api/transfer, /api/payment");

    let store = web::Data::new(AshStore::new());

    HttpServer::new(move || {
        App::new()
            .app_data(store.clone())
            .wrap(middleware::Logger::default())
            .route("/health", web::get().to(health))
            .route("/api/context", web::post().to(issue_context))
            .route("/api/transfer", web::post().to(transfer))
            .route("/api/payment", web::post().to(payment))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
