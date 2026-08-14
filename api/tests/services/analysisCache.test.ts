import {
  buildCacheKey,
  clearAnalysisCache,
  getCachedAnalysis,
  setCachedAnalysis,
} from '../../src/services/analysisCache';

beforeEach(() => {
  clearAnalysisCache();
});

describe('analysisCache', () => {
  it('returns undefined for a key that was never set', () => {
    expect(getCachedAnalysis('missing')).toBeUndefined();
  });

  it('returns the cached value for a key that was set', () => {
    const result = { risk_score: { overall: 1, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 }, findings: [] };
    setCachedAnalysis('key-1', result);
    expect(getCachedAnalysis('key-1')).toEqual(result);
  });

  it('clearAnalysisCache empties all entries', () => {
    setCachedAnalysis('key-1', { risk_score: { overall: 1, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 }, findings: [] });
    clearAnalysisCache();
    expect(getCachedAnalysis('key-1')).toBeUndefined();
  });

  it('buildCacheKey scopes by policy id, content hash, and frameworks', () => {
    const keyA = buildCacheKey('p1', 'hash1', ['cis']);
    const keyB = buildCacheKey('p2', 'hash1', ['cis']);
    const keyC = buildCacheKey('p1', 'hash2', ['cis']);
    const keyD = buildCacheKey('p1', 'hash1', ['hipaa']);
    expect(new Set([keyA, keyB, keyC, keyD]).size).toBe(4);
  });
});
