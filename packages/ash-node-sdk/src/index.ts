// ── Constants ────────────────────────────────────────────────────────
export {
  ASH_SDK_VERSION,
  MAX_PAYLOAD_SIZE,
  MAX_RECURSION_DEPTH,
  MAX_SCOPE_FIELDS,
  MAX_NONCE_LENGTH,
  MIN_NONCE_HEX_CHARS,
  MAX_BINDING_LENGTH,
  MAX_CONTEXT_ID_LENGTH,
  MAX_QUERY_PARAMS,
  MAX_TIMESTAMP,
  SHA256_HEX_LENGTH,
  SCOPE_FIELD_DELIMITER,
  PIPE_DELIMITER,
  DEFAULT_MAX_TIMESTAMP_AGE_SECONDS,
  DEFAULT_CLOCK_SKEW_SECONDS,
} from './constants.js';

// ── Errors ───────────────────────────────────────────────────────────
export { AshError, AshErrorCode } from './errors.js';

// ── Types ────────────────────────────────────────────────────────────
export type { ScopedProofResult, UnifiedProofResult } from './types.js';

// ── Validation ───────────────────────────────────────────────────────
export {
  ashValidateNonce,
  ashValidateTimestampFormat,
  ashValidateTimestamp,
  ashValidateHash,
} from './validate.js';

// ── Canonicalization ─────────────────────────────────────────────────
export {
  ashCanonicalizeJson,
  ashCanonicalizeJsonValue,
  ashCanonicalizeQuery,
  ashCanonicalizeUrlencoded,
} from './canonicalize.js';

// ── Comparison ───────────────────────────────────────────────────────
export { ashTimingSafeEqual } from './compare.js';

// ── Hashing ──────────────────────────────────────────────────────────
export {
  ashHashBody,
  ashHashProof,
  ashHashScope,
} from './hash.js';

// ── Binding ──────────────────────────────────────────────────────────
export {
  ashNormalizeBinding,
  ashNormalizeBindingFromUrl,
} from './binding.js';

// ── Proof (basic) ────────────────────────────────────────────────────
export {
  ashDeriveClientSecret,
  ashBuildProof,
  ashVerifyProof,
  ashVerifyProofWithFreshness,
} from './proof.js';

// ── Proof (scoped) ───────────────────────────────────────────────────
export {
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  ashBuildProofScoped,
  ashVerifyProofScoped,
} from './proof-scoped.js';

// ── Proof (unified) ──────────────────────────────────────────────────
export {
  ashBuildProofUnified,
  ashVerifyProofUnified,
} from './proof-unified.js';

// ── Headers (Phase 2) ──────────────────────────────────────────────
export {
  ashExtractHeaders,
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
} from './headers.js';
export type { AshHeaderBundle } from './headers.js';

// ── Context Store (Phase 2) ────────────────────────────────────────
export { AshMemoryStore } from './context.js';
export type { AshContext, AshContextStore, AshMemoryStoreOptions } from './context.js';

// ── Context Store — Redis (Phase 2) ───────────────────────────────
export { AshRedisStore } from './context-redis.js';
export type { RedisClient, AshRedisStoreOptions } from './context-redis.js';

// ── Scope Policy (Phase 2) ─────────────────────────────────────────
export { AshScopePolicyRegistry } from './scope-policy.js';
export type { ScopePolicy, ScopePolicyMatch } from './scope-policy.js';

// ── Build Orchestrator (Phase 2) ───────────────────────────────────
export { ashBuildRequest } from './build-request.js';
export type { BuildRequestInput, BuildRequestResult } from './build-request.js';

// ── Verify Orchestrator (Phase 2) ──────────────────────────────────
export { ashVerifyRequest } from './verify-request.js';
export type { VerifyRequestInput, VerifyResult } from './verify-request.js';

// ── Middleware Types (Phase 2) ─────────────────────────────────────
export type { AshMiddlewareOptions, AshRequestMeta } from './middleware/types.js';

// ── Express Middleware (Phase 2) ───────────────────────────────────
export { ashExpressMiddleware } from './middleware/express.js';

// ── Fastify Plugin (Phase 2) ──────────────────────────────────────
export { ashFastifyPlugin } from './middleware/fastify.js';

// ── Debug Trace (Phase 3) ────────────────────────────────────────
export {
  ashBuildRequestDebug,
  ashVerifyRequestDebug,
  ashFormatTrace,
} from './debug.js';
export type {
  TraceStep,
  BuildRequestDebugResult,
  VerifyRequestDebugResult,
} from './debug.js';
