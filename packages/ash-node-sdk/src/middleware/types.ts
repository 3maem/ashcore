import type { AshContextStore } from '../context.js';
import type { AshScopePolicyRegistry } from '../scope-policy.js';
import type { AshError } from '../errors.js';

export interface AshMiddlewareOptions {
  store: AshContextStore;
  scopeRegistry?: AshScopePolicyRegistry;
  maxAgeSeconds?: number;
  clockSkewSeconds?: number;
  onError?: (error: AshError, req: unknown, res: unknown) => void;
  extractBody?: (req: unknown) => string | undefined;
}

export interface AshRequestMeta {
  verified: boolean;
  contextId: string;
  mode: 'basic' | 'scoped' | 'unified';
  timestamp: number;
  binding: string;
}
