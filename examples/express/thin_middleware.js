// Express thin-wrapper middleware (ASH v1.0.0)
// Verifies ASH HMAC proofs on incoming requests using @3maem/ash-node-sdk.

import {
  ashVerifyProof,
  ashNormalizeBinding,
  ashHashBody,
  ashCanonicalizeJson,
} from "@3maem/ash-node-sdk";
import { Buffer } from "buffer";

/**
 * ASH verification middleware for Express.
 *
 * Requires:
 * - A `lookupContext(contextId)` function that returns { nonce, binding }
 *   for a stored ASH context, or null if not found.
 * - `express.raw({ type: '*/*' })` or equivalent raw-body parser applied
 *   before this middleware so that `req.body` is a Buffer.
 *
 * @param {object} opts
 * @param {function} opts.lookupContext - async (contextId) => { nonce, binding } | null
 * @param {number}  [opts.maxSkewSecs=300] - unused here; timestamp skew should be
 *   enforced by the context store or by ashVerifyProof if supported.
 */
export default function ashMiddleware({ lookupContext, maxSkewSecs = 300 } = {}) {
  if (typeof lookupContext !== "function") {
    throw new Error("ashMiddleware requires a lookupContext(contextId) function");
  }

  return async function (req, res, next) {
    // 1. Extract ASH headers
    const contextId = req.headers["x-ash-context-id"];
    const proof     = req.headers["x-ash-proof"];
    const timestamp = req.headers["x-ash-timestamp"];

    if (!contextId || !proof || !timestamp) {
      return res.status(460).json({
        code: "ASH_PROOF_INVALID",
        message: "Missing required ASH headers (X-ASH-Context-ID, X-ASH-Proof, X-ASH-Timestamp)",
      });
    }

    // 2. Look up the stored context (nonce + binding)
    let stored;
    try {
      stored = await lookupContext(contextId);
    } catch (err) {
      return res.status(460).json({
        code: "ASH_PROOF_INVALID",
        message: "Context lookup failed",
      });
    }

    if (!stored || !stored.nonce) {
      return res.status(460).json({
        code: "ASH_PROOF_INVALID",
        message: "Unknown or expired context",
      });
    }

    // 3. Compute binding and body hash from the incoming request
    const rawQuery = req.originalUrl.split("?")[1] || "";
    const binding  = ashNormalizeBinding(req.method, req.path, rawQuery);

    const body      = req.body ? Buffer.from(req.body) : Buffer.alloc(0);
    const bodyStr   = body.length > 0 ? body.toString("utf-8") : "";
    const canonical = ashCanonicalizeJson(JSON.stringify(req.body));
    const bodyHash  = ashHashBody(canonical);

    // 4. Verify the proof
    //    ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, clientProof)
    try {
      const valid = ashVerifyProof(
        stored.nonce,
        contextId,
        binding,
        timestamp,
        bodyHash,
        proof,
      );

      if (valid) {
        return next();
      }
    } catch (e) {
      // ashVerifyProof throws structured { code, http_status, message } on error
      const status = (e && e.http_status) || 460;
      return res.status(status).json({
        code: (e && e.code) || "ASH_PROOF_INVALID",
        message: (e && e.message) || "Proof verification failed",
      });
    }

    // Proof did not match
    return res.status(460).json({
      code: "ASH_PROOF_INVALID",
      message: "Proof verification failed",
    });

    // NOTE: In production, replay protection should be implemented here
    // by consuming the context after successful verification (e.g., marking
    // it as used in the context store to prevent replay attacks).
  };
}
