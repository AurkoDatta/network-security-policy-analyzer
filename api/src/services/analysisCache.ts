import type { AnalyzeResult } from './analyzerClient';

const TTL_MS = 5 * 60 * 1000;

interface CacheEntry {
  value: AnalyzeResult;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();

export function buildCacheKey(policyId: string, contentHash: string, frameworks: string[]): string {
  return `${policyId}:${contentHash}:${frameworks.slice().sort().join(',')}`;
}

export function getCachedAnalysis(key: string): AnalyzeResult | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return undefined;
  }
  return entry.value;
}

export function setCachedAnalysis(key: string, value: AnalyzeResult): void {
  cache.set(key, { value, expiresAt: Date.now() + TTL_MS });
}

export function clearAnalysisCache(): void {
  cache.clear();
}
