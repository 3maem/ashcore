/** Result from building a scoped proof. */
export interface ScopedProofResult {
  proof: string;
  scopeHash: string;
}

/** Result from building a unified proof. */
export interface UnifiedProofResult {
  proof: string;
  scopeHash: string;
  chainHash: string;
}
