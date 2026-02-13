"""
ASH Protocol - Python Client Example

This example demonstrates:
1. Getting a context from the server
2. Building an ASH proof for the request
3. Sending a verified request

Run: python client.py (with server running)
"""

import hashlib
import json
from base64 import urlsafe_b64encode

import requests

SERVER_URL = "http://localhost:5000"
ASH_VERSION = "ASHv1"


# =============================================================================
# ASH Client Implementation
# =============================================================================


def canonicalize_json(obj) -> str:
    """Step 1: Canonicalize JSON payload (must match server implementation)."""
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
            json.dumps(key) + ":" + canonicalize_json(obj[key]) for key in sorted_keys
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
    """Step 2: Build ASH proof (must match server implementation)."""
    input_str = f"{ASH_VERSION}\n{mode}\n{binding}\n{context_id}\n"

    if nonce:
        input_str += f"{nonce}\n"

    input_str += canonical_payload

    hash_bytes = hashlib.sha256(input_str.encode("utf-8")).digest()
    return urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")


# =============================================================================
# Example Usage
# =============================================================================


def make_protected_request():
    """Demonstrate complete ASH flow."""
    print("=== ASH Protocol Client Example ===\n")

    # The data we want to send
    request_data = {
        "action": "update",
        "userId": 123,
        "settings": {
            "notifications": True,
            "theme": "dark",
        },
    }

    try:
        # =====================================================================
        # Step 1: Get a context from the server
        # =====================================================================
        print("Step 1: Requesting context from server...")

        binding = "POST /api/protected"
        context_response = requests.get(
            f"{SERVER_URL}/api/context", params={"binding": binding}
        )
        context_response.raise_for_status()

        context = context_response.json()
        print(
            f"  Context received: contextId={context['contextId']}, "
            f"binding={context['binding']}, mode={context['mode']}"
        )

        # =====================================================================
        # Step 2: Canonicalize the payload
        # =====================================================================
        print("\nStep 2: Canonicalizing payload...")

        canonical_payload = canonicalize_json(request_data)
        print(f"  Original: {json.dumps(request_data)}")
        print(f"  Canonical: {canonical_payload}")

        # =====================================================================
        # Step 3: Build the ASH proof
        # =====================================================================
        print("\nStep 3: Building ASH proof...")

        proof = build_proof(
            context["mode"],  # Security mode (balanced)
            context["binding"],  # Endpoint binding (POST /api/protected)
            context["contextId"],  # Server-issued context ID
            context.get("nonce"),  # Server nonce (for strict mode)
            canonical_payload,  # Canonicalized request body
        )
        print(f"  Proof: {proof}")

        # =====================================================================
        # Step 4: Send the protected request
        # =====================================================================
        print("\nStep 4: Sending protected request...")

        response = requests.post(
            f"{SERVER_URL}/api/protected",
            headers={
                "Content-Type": "application/json",
                "X-ASH-Context": context["contextId"],  # Include context ID
                "X-ASH-Proof": proof,  # Include computed proof
            },
            json=request_data,
        )

        result = response.json()

        if response.ok:
            print(f"  Success! Response: {result}")
        else:
            print(f"  Failed! Error: {result}")

        # =====================================================================
        # Step 5: Demonstrate replay protection
        # =====================================================================
        print("\nStep 5: Attempting replay attack (same context)...")

        replay_response = requests.post(
            f"{SERVER_URL}/api/protected",
            headers={
                "Content-Type": "application/json",
                "X-ASH-Context": context["contextId"],
                "X-ASH-Proof": proof,
            },
            json=request_data,
        )

        replay_result = replay_response.json()
        print(f"  Replay attempt result: {replay_result}")
        print("  (Expected: ASH_REPLAY_DETECTED)")

        # =====================================================================
        # Step 6: Demonstrate tamper protection
        # =====================================================================
        print("\nStep 6: Attempting tampered request...")

        # Get a new context for the tamper test
        context2_response = requests.get(
            f"{SERVER_URL}/api/context", params={"binding": binding}
        )
        context2 = context2_response.json()

        # Build proof with original data
        original_data = {"amount": 100}
        original_proof = build_proof(
            context2["mode"],
            context2["binding"],
            context2["contextId"],
            context2.get("nonce"),
            canonicalize_json(original_data),
        )

        # But send different data (tampered!)
        tampered_data = {"amount": 1000000}

        tamper_response = requests.post(
            f"{SERVER_URL}/api/protected",
            headers={
                "Content-Type": "application/json",
                "X-ASH-Context": context2["contextId"],
                "X-ASH-Proof": original_proof,  # Proof for original data
            },
            json=tampered_data,  # But sending tampered data!
        )

        tamper_result = tamper_response.json()
        print(f"  Tamper attempt result: {tamper_result}")
        print("  (Expected: ASH_INTEGRITY_FAILED)")

    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to server")
        print("\nMake sure the server is running: python app.py")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    make_protected_request()
