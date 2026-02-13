import { AshError } from '../errors.js';
import { X_ASH_CONTEXT_ID } from '../headers.js';
import { ashVerifyRequest } from '../verify-request.js';
import type { AshMiddlewareOptions, AshRequestMeta } from './types.js';

/**
 * Extract body string from Express request.
 * Handles pre-parsed JSON body (req.body) and raw string.
 */
function defaultExtractBody(req: unknown): string | undefined {
  const r = req as Record<string, unknown>;
  if (r.body === undefined || r.body === null) return undefined;
  if (typeof r.body === 'string') return r.body;
  // Pre-parsed JSON (express.json() middleware)
  return JSON.stringify(r.body);
}

/**
 * Get header value from Express-like request.
 */
function getContextIdHeader(req: unknown): string | undefined {
  const r = req as Record<string, unknown>;
  if (typeof r.headers === 'object' && r.headers !== null) {
    const headers = r.headers as Record<string, string | string[] | undefined>;
    // Case-insensitive scan
    const lowerName = X_ASH_CONTEXT_ID.toLowerCase();
    for (const key of Object.keys(headers)) {
      if (key.toLowerCase() === lowerName) {
        const val = headers[key];
        if (Array.isArray(val)) return val[0];
        return val;
      }
    }
  }
  return undefined;
}

export interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  path: string;
  query?: Record<string, unknown>;
  originalUrl?: string;
  url?: string;
  body?: unknown;
  ash?: AshRequestMeta;
}

export interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
}

export type ExpressNextFunction = (err?: unknown) => void;

/**
 * Express middleware factory for ASH verification.
 *
 * Usage:
 *   app.use(ashExpressMiddleware({ store }));
 */
export function ashExpressMiddleware(
  options: AshMiddlewareOptions,
): (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => void {
  const { store, scopeRegistry, maxAgeSeconds, clockSkewSeconds, onError, extractBody } = options;

  return async (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => {
    try {
      // Extract context ID from header
      const contextId = getContextIdHeader(req);
      if (!contextId) {
        const err = AshError.proofMissing();
        if (onError) {
          onError(err, req, res);
          return;
        }
        res.status(err.httpStatus).json({
          error: err.code,
          message: err.message,
          status: err.httpStatus,
        });
        return;
      }

      // Consume context from store
      let ctx;
      try {
        ctx = await store.consume(contextId);
      } catch (err: unknown) {
        if (err instanceof AshError) {
          if (onError) {
            onError(err, req, res);
            return;
          }
          res.status(err.httpStatus).json({
            error: err.code,
            message: err.message,
            status: err.httpStatus,
          });
          return;
        }
        throw err;
      }

      // Extract body
      const bodyExtractor = extractBody ?? defaultExtractBody;
      const body = bodyExtractor(req);

      // Extract raw query from URL
      const url = req.originalUrl ?? req.url ?? req.path;
      const qIdx = url.indexOf('?');
      const rawQuery = qIdx !== -1 ? url.slice(qIdx + 1).split('#')[0] : '';

      // Determine scope from registry if available
      let scope: string[] | undefined;
      if (scopeRegistry) {
        const match = scopeRegistry.match(req.method, req.path);
        if (match) {
          scope = match.policy.fields;
        }
      }

      // Verify request
      const result = ashVerifyRequest({
        headers: req.headers,
        method: req.method,
        path: req.path,
        rawQuery,
        body: body ?? '',
        nonce: ctx.nonce,
        contextId: ctx.id,
        scope,
        maxAgeSeconds,
        clockSkewSeconds,
      });

      if (!result.ok) {
        const err = result.error!;
        if (onError) {
          onError(err, req, res);
          return;
        }
        res.status(err.httpStatus).json({
          error: err.code,
          message: err.message,
          status: err.httpStatus,
        });
        return;
      }

      // Attach meta to request
      req.ash = {
        verified: true,
        contextId: ctx.id,
        mode: result.meta!.mode,
        timestamp: result.meta!.timestamp,
        binding: result.meta!.binding,
      };

      next();
    } catch (err: unknown) {
      const ashErr = err instanceof AshError
        ? err
        : AshError.internalError(err instanceof Error ? err.message : 'Unknown error');

      if (onError) {
        onError(ashErr, req, res);
        return;
      }
      res.status(ashErr.httpStatus).json({
        error: ashErr.code,
        message: ashErr.message,
        status: ashErr.httpStatus,
      });
    }
  };
}
