import { AshError } from './errors.js';

// ── Types ──────────────────────────────────────────────────────────

export interface AshContext {
  id: string;
  nonce: string;
  binding: string;
  clientSecret: string;
  used: boolean;
  createdAt: number;
  expiresAt: number;
}

export interface AshContextStore {
  get(id: string): Promise<AshContext | null>;
  consume(id: string): Promise<AshContext>;
  store(ctx: AshContext): Promise<void>;
  cleanup(): Promise<number>;
}

export interface AshMemoryStoreOptions {
  ttlSeconds?: number;
  cleanupIntervalSeconds?: number;
}

// ── Default Values ─────────────────────────────────────────────────

const DEFAULT_TTL_SECONDS = 300;
const DEFAULT_CLEANUP_INTERVAL_SECONDS = 60;

// ── Implementation ─────────────────────────────────────────────────

export class AshMemoryStore implements AshContextStore {
  private readonly _map = new Map<string, AshContext>();
  private readonly _ttlMs: number;
  private _timer: ReturnType<typeof setInterval> | null = null;

  constructor(options?: AshMemoryStoreOptions) {
    const ttl = options?.ttlSeconds ?? DEFAULT_TTL_SECONDS;
    const interval = options?.cleanupIntervalSeconds ?? DEFAULT_CLEANUP_INTERVAL_SECONDS;

    this._ttlMs = ttl * 1000;

    if (interval > 0) {
      this._timer = setInterval(() => { void this.cleanup(); }, interval * 1000);
      // Don't block process exit
      if (this._timer && typeof this._timer === 'object' && 'unref' in this._timer) {
        this._timer.unref();
      }
    }
  }

  async store(ctx: AshContext): Promise<void> {
    const stored: AshContext = {
      ...ctx,
      expiresAt: ctx.expiresAt > 0 ? ctx.expiresAt : ctx.createdAt + this._ttlMs / 1000,
    };
    this._map.set(ctx.id, stored);
  }

  async get(id: string): Promise<AshContext | null> {
    const ctx = this._map.get(id);
    if (!ctx) return null;

    const now = Math.floor(Date.now() / 1000);
    if (now > ctx.expiresAt) {
      this._map.delete(id);
      return null;
    }

    return ctx;
  }

  async consume(id: string): Promise<AshContext> {
    const ctx = this._map.get(id);
    if (!ctx) {
      throw AshError.ctxNotFound();
    }

    const now = Math.floor(Date.now() / 1000);
    if (now > ctx.expiresAt) {
      this._map.delete(id);
      throw AshError.ctxExpired();
    }

    if (ctx.used) {
      throw AshError.ctxAlreadyUsed();
    }

    // Atomic: mark as used
    ctx.used = true;
    return ctx;
  }

  async cleanup(): Promise<number> {
    const now = Math.floor(Date.now() / 1000);
    let removed = 0;

    for (const [id, ctx] of this._map) {
      if (now > ctx.expiresAt) {
        this._map.delete(id);
        removed++;
      }
    }

    return removed;
  }

  destroy(): void {
    if (this._timer !== null) {
      clearInterval(this._timer);
      this._timer = null;
    }
    this._map.clear();
  }

  /** Visible size for testing. */
  get size(): number {
    return this._map.size;
  }
}
