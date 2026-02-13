import { AshError } from './errors.js';

// ── Types ──────────────────────────────────────────────────────────

export interface ScopePolicy {
  pattern: string;
  fields: string[];
  required?: boolean;
}

export interface ScopePolicyMatch {
  policy: ScopePolicy;
  params: Record<string, string>;
}

// ── Limits ─────────────────────────────────────────────────────────

const MAX_PATTERN_LENGTH = 512;
const MAX_WILDCARDS = 8;

// ── Control char + null byte check ─────────────────────────────────

const CONTROL_OR_NULL_RE = /[\x00-\x1F\x7F]/;

// ── Internal: parsed pattern ───────────────────────────────────────

interface ParsedPolicy {
  policy: ScopePolicy;
  method: string;
  pathSegments: Array<{ type: 'literal'; value: string } | { type: 'param'; name: string } | { type: 'wildcard' }>;
}

// ── Implementation ─────────────────────────────────────────────────

export class AshScopePolicyRegistry {
  private readonly _policies: ParsedPolicy[] = [];

  register(policy: ScopePolicy): void {
    // Validate pattern
    if (policy.pattern.length === 0) {
      throw AshError.validationError('Scope policy pattern cannot be empty');
    }

    if (policy.pattern.length > MAX_PATTERN_LENGTH) {
      throw AshError.validationError(
        `Scope policy pattern exceeds maximum length of ${MAX_PATTERN_LENGTH} characters`,
      );
    }

    if (policy.pattern.includes('\0')) {
      throw AshError.validationError('Scope policy pattern must not contain null bytes');
    }

    if (CONTROL_OR_NULL_RE.test(policy.pattern)) {
      throw AshError.validationError('Scope policy pattern must not contain control characters');
    }

    // Count wildcards
    const wildcardCount = (policy.pattern.match(/\*/g) || []).length;
    if (wildcardCount > MAX_WILDCARDS) {
      throw AshError.validationError(
        `Scope policy pattern exceeds maximum of ${MAX_WILDCARDS} wildcards`,
      );
    }

    // Parse: "METHOD /path/segments"
    const spaceIdx = policy.pattern.indexOf(' ');
    if (spaceIdx === -1) {
      throw AshError.validationError(
        'Scope policy pattern must be "METHOD /path" format',
      );
    }

    const method = policy.pattern.slice(0, spaceIdx).toUpperCase();
    const path = policy.pattern.slice(spaceIdx + 1);

    if (!path.startsWith('/')) {
      throw AshError.validationError('Scope policy path must start with /');
    }

    // Parse path segments
    const rawSegments = path.split('/').filter(s => s.length > 0);
    const pathSegments: ParsedPolicy['pathSegments'] = [];

    for (const seg of rawSegments) {
      if (seg === '*') {
        pathSegments.push({ type: 'wildcard' });
      } else if (seg.startsWith(':')) {
        pathSegments.push({ type: 'param', name: seg.slice(1) });
      } else {
        pathSegments.push({ type: 'literal', value: seg });
      }
    }

    this._policies.push({ policy, method, pathSegments });
  }

  match(method: string, path: string): ScopePolicyMatch | null {
    const upperMethod = method.toUpperCase();
    const pathSegments = path.split('/').filter(s => s.length > 0);

    let bestMatch: { parsed: ParsedPolicy; params: Record<string, string>; priority: number } | null = null;

    for (const parsed of this._policies) {
      if (parsed.method !== upperMethod) continue;

      const result = this._tryMatch(parsed.pathSegments, pathSegments);
      if (result === null) continue;

      // Priority: exact (3) > param (2) > wildcard (1)
      if (bestMatch === null || result.priority > bestMatch.priority) {
        bestMatch = { parsed, params: result.params, priority: result.priority };
      }
    }

    if (bestMatch === null) return null;

    return {
      policy: bestMatch.parsed.policy,
      params: bestMatch.params,
    };
  }

  has(pattern: string): boolean {
    return this._policies.some(p => p.policy.pattern === pattern);
  }

  clear(): void {
    this._policies.length = 0;
  }

  get size(): number {
    return this._policies.length;
  }

  private _tryMatch(
    policySegs: ParsedPolicy['pathSegments'],
    pathSegs: string[],
  ): { params: Record<string, string>; priority: number } | null {
    // Check for trailing wildcard
    const hasTrailingWildcard =
      policySegs.length > 0 && policySegs[policySegs.length - 1].type === 'wildcard';

    if (hasTrailingWildcard) {
      // Wildcard can match any remaining segments
      if (pathSegs.length < policySegs.length - 1) return null;
    } else {
      // Exact segment count match required
      if (pathSegs.length !== policySegs.length) return null;
    }

    const params: Record<string, string> = {};
    let priority = 3; // Start at highest, downgrade on param/wildcard

    const checkLength = hasTrailingWildcard ? policySegs.length - 1 : policySegs.length;

    for (let i = 0; i < checkLength; i++) {
      const policySeg = policySegs[i];

      if (policySeg.type === 'literal') {
        if (pathSegs[i] !== policySeg.value) return null;
      } else if (policySeg.type === 'param') {
        params[policySeg.name] = pathSegs[i];
        if (priority > 2) priority = 2;
      } else if (policySeg.type === 'wildcard') {
        if (priority > 1) priority = 1;
      }
    }

    if (hasTrailingWildcard && priority > 1) {
      priority = 1;
    }

    return { params, priority };
  }
}
