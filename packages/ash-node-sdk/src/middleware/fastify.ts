import { AshError } from '../errors.js';
import { X_ASH_CONTEXT_ID } from '../headers.js';
import { ashVerifyRequest } from '../verify-request.js';
import type { AshMiddlewareOptions, AshRequestMeta } from './types.js';

// ── Fastify-compatible interfaces (peer dep only) ──────────────────

export interface FastifyRequest {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  url: string;
  body?: unknown;
  ash?: AshRequestMeta;
}

export interface FastifyReply {
  code(statusCode: number): FastifyReply;
  send(payload: unknown): void;
}

export interface FastifyInstance {
  decorateRequest(property: string, value: unknown): void;
  addHook(
    hookName: string,
    handler: (request: FastifyRequest, reply: FastifyReply) => Promise<void>,
  ): void;
}

// ── Helpers ────────────────────────────────────────────────────────

function getContextIdHeader(req: FastifyRequest): string | undefined {
  const lowerName = X_ASH_CONTEXT_ID.toLowerCase();
  for (const key of Object.keys(req.headers)) {
    if (key.toLowerCase() === lowerName) {
      const val = req.headers[key];
      if (Array.isArray(val)) return val[0];
      return val;
    }
  }
  return undefined;
}

function defaultExtractBody(req: FastifyRequest): string | undefined {
  if (req.body === undefined || req.body === null) return undefined;
  if (typeof req.body === 'string') return req.body;
  return JSON.stringify(req.body);
}

function extractPathAndQuery(url: string): { path: string; rawQuery: string } {
  const hashIdx = url.indexOf('#');
  const clean = hashIdx !== -1 ? url.slice(0, hashIdx) : url;
  const qIdx = clean.indexOf('?');
  if (qIdx === -1) return { path: clean, rawQuery: '' };
  return { path: clean.slice(0, qIdx), rawQuery: clean.slice(qIdx + 1) };
}

function sendError(reply: FastifyReply, err: AshError): void {
  reply.code(err.httpStatus).send({
    error: err.code,
    message: err.message,
    status: err.httpStatus,
  });
}

// ── Plugin ─────────────────────────────────────────────────────────

/**
 * Fastify plugin for ASH verification.
 *
 * Usage:
 *   fastify.register(ashFastifyPlugin, { store });
 */
export async function ashFastifyPlugin(
  fastify: FastifyInstance,
  options: AshMiddlewareOptions,
): Promise<void> {
  const { store, scopeRegistry, maxAgeSeconds, clockSkewSeconds, onError, extractBody } = options;

  // Decorate request with ash property
  fastify.decorateRequest('ash', null);

  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Extract context ID
      const contextId = getContextIdHeader(request);
      if (!contextId) {
        const err = AshError.proofMissing();
        if (onError) {
          onError(err, request, reply);
          return;
        }
        sendError(reply, err);
        return;
      }

      // Consume context
      let ctx;
      try {
        ctx = await store.consume(contextId);
      } catch (err: unknown) {
        if (err instanceof AshError) {
          if (onError) {
            onError(err, request, reply);
            return;
          }
          sendError(reply, err);
          return;
        }
        throw err;
      }

      // Extract body
      const bodyExtractor = extractBody ?? defaultExtractBody;
      const body = (bodyExtractor as (req: unknown) => string | undefined)(request);

      // Parse path and query from URL
      const { path, rawQuery } = extractPathAndQuery(request.url);

      // Determine scope
      let scope: string[] | undefined;
      if (scopeRegistry) {
        const match = scopeRegistry.match(request.method, path);
        if (match) {
          scope = match.policy.fields;
        }
      }

      // Verify
      const result = ashVerifyRequest({
        headers: request.headers,
        method: request.method,
        path,
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
          onError(err, request, reply);
          return;
        }
        sendError(reply, err);
        return;
      }

      // Decorate
      request.ash = {
        verified: true,
        contextId: ctx.id,
        mode: result.meta!.mode,
        timestamp: result.meta!.timestamp,
        binding: result.meta!.binding,
      };
    } catch (err: unknown) {
      const ashErr = err instanceof AshError
        ? err
        : AshError.internalError(err instanceof Error ? err.message : 'Unknown error');

      if (onError) {
        onError(ashErr, request, reply);
        return;
      }
      sendError(reply, ashErr);
    }
  });
}
