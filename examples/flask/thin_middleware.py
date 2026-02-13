# Flask thin-wrapper example (ASH v1.0.0)
# Must use raw request.data bytes.

import time

from flask import Flask, request, jsonify
from ash.core.proof import ash_verify_proof, ash_build_proof_hmac, ash_derive_client_secret
from ash.core.canonicalize import ash_normalize_binding, ash_hash_body, ash_canonicalize_json

app = Flask(__name__)


class HeaderMapView:
    def __init__(self, headers):
        self._headers = headers

    def get_all_ci(self, name: str):
        # Flask headers are case-insensitive; may have multiple values via getlist
        try:
            return self._headers.getlist(name)
        except Exception:
            v = self._headers.get(name)
            return [] if v is None else [v]


def lookup_context(context_id):
    """Look up a stored ASH context by ID.

    In production, this should retrieve the context from a persistent store
    (e.g., Redis) and return a dict with 'nonce' and 'binding' keys,
    or None if the context is not found or expired.
    """
    # TODO: Replace with actual context store lookup
    return None


@app.before_request
def ash_verify():
    # 1. Extract ASH headers
    context_id = request.headers.get("X-ASH-Context-ID")
    client_proof = request.headers.get("X-ASH-Proof")
    timestamp = request.headers.get("X-ASH-Timestamp")

    if not context_id or not client_proof or not timestamp:
        resp = jsonify({"code": "ASH_PROOF_INVALID", "message": "Missing required ASH headers"})
        resp.status_code = 460
        return resp

    # 2. Look up context
    stored = lookup_context(context_id)
    if not stored or not stored.get("nonce"):
        resp = jsonify({"code": "ASH_PROOF_INVALID", "message": "Unknown or expired context"})
        resp.status_code = 460
        return resp

    nonce = stored["nonce"]

    # 3. Normalize binding from the incoming request
    binding = ash_normalize_binding(
        request.method,
        request.path,
        request.query_string.decode("utf-8", errors="replace"),
    )

    # 4. Hash the canonical body
    body_hash = ash_hash_body(
        ash_canonicalize_json(request.get_data(as_text=True) or "")
    )

    # 5. Verify the proof
    valid = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, client_proof)

    if valid:
        # NOTE: In production, replay protection (context consumption) should be
        # implemented here to prevent the same context from being reused.
        return None

    resp = jsonify({"code": "ASH_PROOF_INVALID", "message": "Proof verification failed"})
    resp.status_code = 460
    return resp
