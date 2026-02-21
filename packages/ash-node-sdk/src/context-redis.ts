import { AshError } from './errors.js';
import type { AshContext, AshContextStore } from './context.js';

// ── Redis-compatible interface (peer dep via duck-typing) ─────────

/**
 * Minimal Redis client interface.
 * Compatible with ioredis, node-redis, and any client that exposes these methods.
 */
export interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: unknown[]): Promise<unknown>;
  del(key: string | string[]): Promise<number>;
  eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
}

// ── Options ───────────────────────────────────────────────────────

export interface AshRedisStoreOptions {
  /** Redis client instance (ioredis, node-redis, etc.) */
  client: RedisClient;
  /** Key prefix for all ASH context entries. Default: "ash:ctx:" */
  keyPrefix?: string;
  /** TTL in seconds for context entries. Default: 300 (5 minutes) */
  ttlSeconds?: number;
}

// ── Lua Scripts ───────────────────────────────────────────────────

/**
 * Atomic consume via Lua: get → check expiry → check used → mark used → return.
 * Returns JSON string on success, or error string on failure.
 */
const CONSUME_LUA = `
local val = redis.call('GET', KEYS[1])
if not val then
  return 'ERR:CTX_NOT_FOUND'
end
local ctx = cjson.decode(val)
if ctx.used then
  return 'ERR:CTX_ALREADY_USED'
end
ctx.used = true
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
  redis.call('SET', KEYS[1], cjson.encode(ctx), 'EX', ttl)
else
  redis.call('SET', KEYS[1], cjson.encode(ctx))
end
return val
`;

// ── Implementation ────────────────────────────────────────────────

export class AshRedisStore implements AshContextStore {
  private readonly _client: RedisClient;
  private readonly _prefix: string;
  private readonly _ttlSeconds: number;

  constructor(options: AshRedisStoreOptions) {
    this._client = options.client;
    this._prefix = options.keyPrefix ?? 'ash:ctx:';
    this._ttlSeconds = options.ttlSeconds ?? 300;
  }

  private _key(id: string): string {
    return `${this._prefix}${id}`;
  }

  async store(ctx: AshContext): Promise<void> {
    const ttl = ctx.expiresAt > 0
      ? Math.max(1, ctx.expiresAt - Math.floor(Date.now() / 1000))
      : this._ttlSeconds;

    const payload = JSON.stringify({
      id: ctx.id,
      nonce: ctx.nonce,
      binding: ctx.binding,
      clientSecret: ctx.clientSecret,
      used: ctx.used,
      createdAt: ctx.createdAt,
      expiresAt: ctx.expiresAt > 0 ? ctx.expiresAt : ctx.createdAt + this._ttlSeconds,
    });

    await this._client.set(this._key(ctx.id), payload, 'EX', ttl);
  }

  async get(id: string): Promise<AshContext | null> {
    const raw = await this._client.get(this._key(id));
    if (!raw) return null;

    const ctx = JSON.parse(raw) as AshContext;

    // Double-check expiry (Redis TTL is authoritative, but be safe)
    const now = Math.floor(Date.now() / 1000);
    if (ctx.expiresAt > 0 && now > ctx.expiresAt) {
      await this._client.del(this._key(id));
      return null;
    }

    return ctx;
  }

  async consume(id: string): Promise<AshContext> {
    const result = await this._client.eval(CONSUME_LUA, 1, this._key(id));

    if (result === 'ERR:CTX_NOT_FOUND') {
      throw AshError.ctxNotFound();
    }
    if (result === 'ERR:CTX_ALREADY_USED') {
      throw AshError.ctxAlreadyUsed();
    }

    // result is the original JSON (before marking used)
    const ctx = JSON.parse(result as string) as AshContext;

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (ctx.expiresAt > 0 && now > ctx.expiresAt) {
      await this._client.del(this._key(id));
      throw AshError.ctxExpired();
    }

    return ctx;
  }

  async cleanup(): Promise<number> {
    // Redis handles expiry natively via TTL — no manual cleanup needed
    return 0;
  }

  async destroy(): Promise<void> {
    // No-op: Redis client lifecycle is managed externally
  }
}
