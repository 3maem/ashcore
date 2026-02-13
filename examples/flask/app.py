"""
ASH Integration Example: Flask Server

This example demonstrates how to integrate ASH with Flask
for request integrity verification and anti-replay protection.
"""

from flask import Flask, request, jsonify
from functools import wraps
import time

from ash.core import (
    ash_canonicalize_json,
    ash_normalize_binding,
    ash_derive_client_secret,
    ash_build_proof_hmac,
    ash_verify_proof,
    ash_hash_body,
)
from ash.server import context
from ash.server.stores import Memory as MemoryStore

app = Flask(__name__)

# Initialize ASH store (use Redis in production)
ash_store = MemoryStore(suppress_warning=True)


def ash_protected(f):
    """Decorator to protect endpoints with ASH verification."""
    @wraps(f)
    async def decorated(*args, **kwargs):
        # Get ASH headers
        context_id = request.headers.get('X-ASH-Context-ID')
        timestamp = request.headers.get('X-ASH-Timestamp')
        proof = request.headers.get('X-ASH-Proof')

        if not all([context_id, timestamp, proof]):
            return jsonify({'error': 'Missing ASH headers'}), 403

        # Get stored context
        stored = await ash_store.get(context_id)
        if not stored:
            return jsonify({'error': 'Context not found', 'code': 'ASH_CTX_NOT_FOUND'}), 403

        # Check expiration
        now_ms = int(time.time() * 1000)
        if now_ms > stored.expires_at:
            return jsonify({'error': 'Context expired', 'code': 'ASH_CTX_EXPIRED'}), 403

        # Build binding
        binding = ash_normalize_binding(request.method, request.path, request.query_string.decode())

        # Get body hash
        body = request.get_data(as_text=True) or '{}'
        body_hash = ash_hash_body(body)

        # Verify proof
        is_valid = ash_verify_proof(
            stored.nonce,
            context_id,
            binding,
            timestamp,
            body_hash,
            proof
        )

        if not is_valid:
            return jsonify({'error': 'Invalid proof', 'code': 'ASH_PROOF_MISMATCH'}), 403

        # Consume context (prevent replay)
        result = await ash_store.consume(context_id, now_ms)
        if result != 'consumed':
            return jsonify({'error': 'Context already used', 'code': 'ASH_CTX_USED'}), 403

        return await f(*args, **kwargs)
    return decorated


@app.route('/api/context', methods=['POST'])
async def issue_context():
    """Issue a new ASH context."""
    data = request.get_json() or {}
    endpoint = data.get('endpoint', '/api/transfer')
    ttl_ms = data.get('ttlMs', 30000)

    binding = ash_normalize_binding('POST', endpoint, '')

    ctx = await context.create(
        ash_store,
        binding=binding,
        ttl_ms=ttl_ms,
        issue_nonce=True
    )

    # Derive client secret from nonce
    client_secret = ash_derive_client_secret(ctx.nonce, ctx.context_id, binding)

    return jsonify({
        'contextId': ctx.context_id,
        'clientSecret': client_secret,
        'expiresAt': ctx.expires_at,
    })


@app.route('/api/transfer', methods=['POST'])
@ash_protected
async def transfer():
    """Protected endpoint: Money transfer."""
    data = request.get_json()

    from_account = data.get('fromAccount')
    to_account = data.get('toAccount')
    amount = data.get('amount')

    print(f"Transfer: {amount} from {from_account} to {to_account}")

    return jsonify({
        'success': True,
        'message': 'Transfer completed',
        'transactionId': f'TXN_{int(time.time() * 1000)}',
    })


@app.route('/api/payment', methods=['POST'])
@ash_protected
async def payment():
    """Protected endpoint: Payment."""
    data = request.get_json()

    merchant_id = data.get('merchantId')
    amount = data.get('amount')
    currency = data.get('currency', 'USD')

    print(f"Payment: {amount} {currency} to merchant {merchant_id}")

    return jsonify({
        'success': True,
        'paymentId': f'PAY_{int(time.time() * 1000)}',
    })


@app.route('/health')
def health():
    """Health check endpoint (unprotected)."""
    return jsonify({
        'status': 'ok',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    })


@app.errorhandler(Exception)
def handle_error(error):
    """Global error handler."""
    return jsonify({
        'error': str(error),
        'type': type(error).__name__
    }), 500


if __name__ == '__main__':
    print("ASH Flask example running on port 5000")
    print("Protected endpoints: /api/transfer, /api/payment")
    app.run(debug=False, port=5000)  # Set debug=True only in development with trusted networks
