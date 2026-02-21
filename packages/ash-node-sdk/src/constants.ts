// ashcore constants — matching Rust reference implementation

/** ASH SDK version (library version). */
export const ASH_SDK_VERSION = '1.0.0';

// ── Limits ──────────────────────────────────────────────────────────

/** Maximum payload size in bytes for canonicalization (10 MB). */
export const MAX_PAYLOAD_SIZE = 10 * 1024 * 1024;

/** Maximum recursion depth for JSON canonicalization. */
export const MAX_RECURSION_DEPTH = 64;

/** Maximum number of scope fields. */
export const MAX_SCOPE_FIELDS = 100;

/** Maximum scope field name length. */
export const MAX_SCOPE_FIELD_NAME_LENGTH = 64;

/** Maximum total scope string length after canonicalization. */
export const MAX_TOTAL_SCOPE_LENGTH = 4096;

/** Maximum nonce length in characters. */
export const MAX_NONCE_LENGTH = 512;

/** Minimum hex characters for a valid nonce (128 bits entropy). */
export const MIN_NONCE_HEX_CHARS = 32;

/** Maximum binding length to prevent memory exhaustion. */
export const MAX_BINDING_LENGTH = 8192;

/** Maximum context_id length. */
export const MAX_CONTEXT_ID_LENGTH = 256;

/** Maximum query parameters before rejection. */
export const MAX_QUERY_PARAMS = 1024;

/** Maximum array index in scope paths. */
export const MAX_ARRAY_INDEX = 10000;

/** Maximum total array elements during scope extraction. */
export const MAX_TOTAL_ARRAY_ALLOCATION = 10000;

/** Maximum scope path depth. */
export const MAX_SCOPE_PATH_DEPTH = 32;

/** Maximum reasonable timestamp (year 3000 in Unix time). */
export const MAX_TIMESTAMP = 32503680000;

/** Expected length of SHA-256 hash in hex (32 bytes = 64 hex chars). */
export const SHA256_HEX_LENGTH = 64;

// ── Delimiters ──────────────────────────────────────────────────────

/** Scope field delimiter (unit separator U+001F). */
export const SCOPE_FIELD_DELIMITER = '\x1F';

/** Pipe delimiter for binding format. */
export const PIPE_DELIMITER = '|';

// ── Timestamp ───────────────────────────────────────────────────────

/** Default maximum age for timestamps (5 minutes). */
export const DEFAULT_MAX_TIMESTAMP_AGE_SECONDS = 300;

/** Default clock skew tolerance (30 seconds). */
export const DEFAULT_CLOCK_SKEW_SECONDS = 30;
