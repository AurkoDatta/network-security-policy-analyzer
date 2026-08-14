import { analyzeRulesViaAnalyzer, parsePolicyViaAnalyzer } from '../../src/services/analyzerClient';

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  jest.restoreAllMocks();
});

describe('parsePolicyViaAnalyzer', () => {
  it('posts multipart form data and returns parsed rules', async () => {
    const mockRules = [{ id: 'r1', protocol: 'tcp' }];
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => mockRules,
    }) as unknown as typeof fetch;

    const result = await parsePolicyViaAnalyzer(Buffer.from('{}'), 'firewall', 'rules.json');

    expect(result).toEqual(mockRules);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/parse'),
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('throws with the analyzer error detail when the response is not ok', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ detail: 'Unsupported source_type: bogus' }),
    }) as unknown as typeof fetch;

    await expect(parsePolicyViaAnalyzer(Buffer.from('{}'), 'bogus', 'rules.json')).rejects.toThrow(
      'Unsupported source_type: bogus',
    );
  });

  it('falls back to a generic error when the response body is not valid JSON', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 502,
      json: async () => {
        throw new Error('not json');
      },
    }) as unknown as typeof fetch;

    await expect(parsePolicyViaAnalyzer(Buffer.from('{}'), 'firewall', 'rules.json')).rejects.toThrow(
      'Analyzer request failed with status 502',
    );
  });
});

describe('analyzeRulesViaAnalyzer', () => {
  it('posts JSON and returns risk score and findings', async () => {
    const mockResponse = { risk_score: { overall: 10 }, findings: [] };
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => mockResponse,
    }) as unknown as typeof fetch;

    const result = await analyzeRulesViaAnalyzer([], ['cis']);

    expect(result).toEqual(mockResponse);
  });
});
