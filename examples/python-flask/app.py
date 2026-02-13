"""
ASH Protocol - Python Flask Server Example

This example demonstrates:
1. Issuing a context for a protected endpoint
2. Verifying requests with ASH proof

Run: flask run --port 5000
"""

import hashlib
import hmac
import json
import os
import time
from base64 import urlsafe_b64encode
from functools import wraps

from flask import Flask, jsonify, request

app = Flask(__name__)

# =============================================================================
# ASH Implementation (simplified for demonstration)
# In production, use the ash-python-sdk package
# =============================================================================

ASH_VERSION = "ASHv1"

# In-memory context store (use Redis in production)
context_store: dict = {}


def generate_context_id() -> str:
    """Step 1: Generate a unique context ID."""
    return "ctx_" + os.urandom(16).hex()


def generate_nonce() -> str:
    """Step 2: Generate server nonce for strict mode."""
    return os.urandom(32).hex()


def canonicalize_json(obj) -> str:
    """
    Step 3: Canonicalize JSON payload.
    - Minified (no whitespace)
    - Object keys sorted alphabetically
    - Arrays preserve order
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        # Handle -0 -> 0
        if obj == 0:
            return "0"
        # No scientific notation, remove trailing zeros
        if isinstance(obj, float) and obj == int(obj):
            return str(int(obj))
        return str(obj)
    if isinstance(obj, str):
        return json.dumps(obj)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize_json(item) for item in obj) + "]"
    if isinstance(obj, dict):
        # Sort keys alphabetically
        sorted_keys = sorted(obj.keys())
        pairs = [
            json.dumps(key) + ":" + canonicalize_json(obj[key])
            for key in sorted_keys
        ]
        return "{" + ",".join(pairs) + "}"
    raise ValueError(f"Unsupported type: {type(obj)}")


def build_proof(
    mode: str,
    binding: str,
    context_id: str,
    nonce: str | None,
    canonical_payload: str,
) -> str:
    """
    Step 4: Build ASH proof.

    Proof = SHA256(
      "ASHv1" + "\\n" +
      mode + "\\n" +
      binding + "\\n" +
      contextId + "\\n" +
      (nonce? + "\\n" : "") +
      canonicalPayload
    )

    Output: Base64URL encoded (no padding)
    """
    input_str = f"{ASH_VERSION}\n{mode}\n{binding}\n{context_id}\n"

    # Add nonce if present (strict mode)
    if nonce:
        input_str += f"{nonce}\n"

    input_str += canonical_payload

    # Hash with SHA-256
    hash_bytes = hashlib.sha256(input_str.encode("utf-8")).digest()

    # Encode as Base64URL (no padding)
    return urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")


def timing_safe_equal(a: str, b: str) -> bool:
    """Step 5: Constant-time string comparison (prevents timing attacks)."""
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# =============================================================================
# ASH Middleware Decorator
# =============================================================================


def ash_protected(expected_binding: str):
    """Decorator to protect an endpoint with ASH verification."""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Step 1: Extract ASH headers
            context_id = request.headers.get("X-ASH-Context")
            client_proof = request.headers.get("X-ASH-Proof")

            if not context_id or not client_proof:
                return (
                    jsonify(
                        {
                            "error": "ASH_MISSING_HEADERS",
                            "message": "Missing X-ASH-Context or X-ASH-Proof headers",
                        }
                    ),
                    401,
                )

            # Step 2: Retrieve context from store
            context = context_store.get(context_id)

            if not context:
                return (
                    jsonify(
                        {
                            "error": "ASH_INVALID_CONTEXT",
                            "message": "Context not found or expired",
                        }
                    ),
                    401,
                )

            # Step 3: Check if context expired
            if time.time() * 1000 > context["expires_at"]:
                del context_store[context_id]
                return (
                    jsonify(
                        {
                            "error": "ASH_CONTEXT_EXPIRED",
                            "message": "Context has expired",
                        }
                    ),
                    401,
                )

            # Step 4: Check for replay (already used)
            if context["used"]:
                return (
                    jsonify(
                        {
                            "error": "ASH_REPLAY_DETECTED",
                            "message": "Context already used (replay attack detected)",
                        }
                    ),
                    401,
                )

            # Step 5: Verify binding matches
            if context["binding"] != expected_binding:
                return (
                    jsonify(
                        {
                            "error": "ASH_ENDPOINT_MISMATCH",
                            "message": f"Binding mismatch: expected {context['binding']}, "
                            f"got {expected_binding}",
                        }
                    ),
                    401,
                )

            # Step 6: Canonicalize the request payload
            try:
                payload = request.get_json(force=True) or {}
                canonical_payload = canonicalize_json(payload)
            except Exception as e:
                return (
                    jsonify(
                        {
                            "error": "ASH_CANONICALIZATION_FAILED",
                            "message": f"Failed to canonicalize payload: {e}",
                        }
                    ),
                    400,
                )

            # Step 7: Build expected proof
            expected_proof = build_proof(
                context["mode"],
                context["binding"],
                context_id,
                context.get("nonce"),
                canonical_payload,
            )

            # Step 8: Verify proof using constant-time comparison
            if not timing_safe_equal(expected_proof, client_proof):
                return (
                    jsonify(
                        {
                            "error": "ASH_INTEGRITY_FAILED",
                            "message": "Proof verification failed - request may have been tampered",
                        }
                    ),
                    401,
                )

            # Step 9: Mark context as used (prevents replay)
            context["used"] = True

            print(f"[ASH] Verified request with context: {context_id}")

            # Step 10: Call the actual endpoint handler
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# =============================================================================
# API Endpoints
# =============================================================================


@app.route("/api/context", methods=["GET"])
def issue_context():
    """
    Context Issuance Endpoint

    Client calls this before making a protected request.
    Returns a context ID that must be included with the protected request.
    """
    # Step 1: Determine which endpoint this context is for
    binding = request.args.get("binding", "POST /api/protected")
    mode = request.args.get("mode", "balanced")

    # Step 2: Generate context ID
    context_id = generate_context_id()

    # Step 3: Calculate expiration (30 seconds)
    ttl_ms = 30000
    expires_at = int(time.time() * 1000) + ttl_ms

    # Step 4: Generate nonce for strict mode
    nonce = generate_nonce() if mode == "strict" else None

    # Step 5: Store context
    context_store[context_id] = {
        "id": context_id,
        "binding": binding,
        "mode": mode,
        "expires_at": expires_at,
        "used": False,
        "nonce": nonce,
    }

    print(f"[ASH] Issued context: {context_id} for {binding}")

    # Step 6: Return context to client
    response = {
        "contextId": context_id,
        "binding": binding,
        "mode": mode,
        "expiresAt": expires_at,
    }

    # Only return nonce in strict mode
    if nonce:
        response["nonce"] = nonce

    return jsonify(response)


@app.route("/api/protected", methods=["POST"])
@ash_protected("POST /api/protected")
def protected_endpoint():
    """
    Protected Endpoint

    Requires valid ASH context and proof.
    The @ash_protected decorator handles verification.
    """
    data = request.get_json()
    return jsonify(
        {
            "success": True,
            "message": "Request verified and processed",
            "data": data,
        }
    )


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint (unprotected)."""
    return jsonify({"status": "ok", "contexts": len(context_store)})


if __name__ == "__main__":
    print("ASH Flask Example Server running on http://localhost:5000")
    print("")
    print("Endpoints:")
    print("  GET  /api/context    - Issue a new context")
    print("  POST /api/protected  - Protected endpoint (requires ASH)")
    print("  GET  /health         - Health check")
    app.run(host="127.0.0.1", port=5000, debug=False)  # Set debug=True only in development with trusted networks
