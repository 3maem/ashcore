/**
 * ASH error codes matching the Rust ashcore reference implementation.
 * Every code maps to a unique HTTP status for unambiguous identification.
 */
export enum AshErrorCode {
  CTX_NOT_FOUND = 'ASH_CTX_NOT_FOUND',
  CTX_EXPIRED = 'ASH_CTX_EXPIRED',
  CTX_ALREADY_USED = 'ASH_CTX_ALREADY_USED',
  PROOF_INVALID = 'ASH_PROOF_INVALID',
  BINDING_MISMATCH = 'ASH_BINDING_MISMATCH',
  SCOPE_MISMATCH = 'ASH_SCOPE_MISMATCH',
  CHAIN_BROKEN = 'ASH_CHAIN_BROKEN',
  SCOPED_FIELD_MISSING = 'ASH_SCOPED_FIELD_MISSING',
  TIMESTAMP_INVALID = 'ASH_TIMESTAMP_INVALID',
  PROOF_MISSING = 'ASH_PROOF_MISSING',
  CANONICALIZATION_ERROR = 'ASH_CANONICALIZATION_ERROR',
  VALIDATION_ERROR = 'ASH_VALIDATION_ERROR',
  MODE_VIOLATION = 'ASH_MODE_VIOLATION',
  UNSUPPORTED_CONTENT_TYPE = 'ASH_UNSUPPORTED_CONTENT_TYPE',
  INTERNAL_ERROR = 'ASH_INTERNAL_ERROR',
}

/** Map from AshErrorCode to HTTP status code. */
const HTTP_STATUS_MAP: Record<AshErrorCode, number> = {
  [AshErrorCode.CTX_NOT_FOUND]: 450,
  [AshErrorCode.CTX_EXPIRED]: 451,
  [AshErrorCode.CTX_ALREADY_USED]: 452,
  [AshErrorCode.PROOF_INVALID]: 460,
  [AshErrorCode.BINDING_MISMATCH]: 461,
  [AshErrorCode.SCOPE_MISMATCH]: 473,
  [AshErrorCode.CHAIN_BROKEN]: 474,
  [AshErrorCode.SCOPED_FIELD_MISSING]: 475,
  [AshErrorCode.TIMESTAMP_INVALID]: 482,
  [AshErrorCode.PROOF_MISSING]: 483,
  [AshErrorCode.CANONICALIZATION_ERROR]: 484,
  [AshErrorCode.VALIDATION_ERROR]: 485,
  [AshErrorCode.MODE_VIOLATION]: 486,
  [AshErrorCode.UNSUPPORTED_CONTENT_TYPE]: 415,
  [AshErrorCode.INTERNAL_ERROR]: 500,
};

/** Retryable error codes (transient conditions). */
const RETRYABLE_CODES = new Set([
  AshErrorCode.TIMESTAMP_INVALID,
  AshErrorCode.INTERNAL_ERROR,
  AshErrorCode.CTX_ALREADY_USED,
]);

/**
 * Structured error type for ASH operations.
 * Error messages are safe for logging — they never contain sensitive data.
 */
export class AshError extends Error {
  readonly code: AshErrorCode;
  readonly httpStatus: number;
  readonly retryable: boolean;

  constructor(code: AshErrorCode, message: string) {
    super(message);
    this.name = 'AshError';
    this.code = code;
    this.httpStatus = HTTP_STATUS_MAP[code];
    this.retryable = RETRYABLE_CODES.has(code);
  }

  // ── Convenience factories ──────────────────────────────────────────

  static ctxNotFound(): AshError {
    return new AshError(AshErrorCode.CTX_NOT_FOUND, 'Context not found');
  }

  static ctxExpired(): AshError {
    return new AshError(AshErrorCode.CTX_EXPIRED, 'Context has expired');
  }

  static ctxAlreadyUsed(): AshError {
    return new AshError(AshErrorCode.CTX_ALREADY_USED, 'Context already consumed');
  }

  static proofInvalid(): AshError {
    return new AshError(AshErrorCode.PROOF_INVALID, 'Proof verification failed');
  }

  static proofMissing(): AshError {
    return new AshError(AshErrorCode.PROOF_MISSING, 'Required proof not provided');
  }

  static bindingMismatch(): AshError {
    return new AshError(AshErrorCode.BINDING_MISMATCH, 'Binding does not match endpoint');
  }

  static canonicalizationError(): AshError {
    return new AshError(AshErrorCode.CANONICALIZATION_ERROR, 'Failed to canonicalize payload');
  }

  static validationError(message: string): AshError {
    return new AshError(AshErrorCode.VALIDATION_ERROR, message);
  }

  static timestampInvalid(message: string): AshError {
    return new AshError(AshErrorCode.TIMESTAMP_INVALID, message);
  }

  static scopedFieldMissing(field: string): AshError {
    return new AshError(AshErrorCode.SCOPED_FIELD_MISSING, `Required scoped field missing: ${field}`);
  }

  static scopeMismatch(message: string): AshError {
    return new AshError(AshErrorCode.SCOPE_MISMATCH, message);
  }

  static chainBroken(message: string): AshError {
    return new AshError(AshErrorCode.CHAIN_BROKEN, message);
  }

  static internalError(message: string): AshError {
    return new AshError(AshErrorCode.INTERNAL_ERROR, message);
  }
}
