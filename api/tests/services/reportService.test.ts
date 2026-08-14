import { generateReportPdf } from '../../src/services/reportService';

describe('generateReportPdf', () => {
  it('produces a non-empty PDF buffer containing finding descriptions', async () => {
    const policy = { name: 'test-policy', source_type: 'firewall' } as never;
    const analysis = {
      risk_score: { overall: 55, permissiveness: 60, exposure: 40, compliance_violations: 30, unused: 10 },
      findings: [
        {
          type: 'overly_permissive',
          severity: 'high',
          rule_id: 'r1',
          description: 'Allows traffic from 0.0.0.0/0',
          recommendation: 'Restrict the source CIDR.',
        },
      ],
      generated_at: new Date('2026-01-01'),
    } as never;

    const buffer = await generateReportPdf(policy, analysis);

    expect(buffer.length).toBeGreaterThan(0);
    expect(buffer.subarray(0, 4).toString()).toBe('%PDF');
  });

  it('produces a valid PDF when there are no findings', async () => {
    const policy = { name: 'clean-policy', source_type: 'firewall' } as never;
    const analysis = {
      risk_score: { overall: 0, permissiveness: 0, exposure: 0, compliance_violations: 0, unused: 0 },
      findings: [],
      generated_at: new Date('2026-01-01'),
    } as never;

    const buffer = await generateReportPdf(policy, analysis);

    expect(buffer.subarray(0, 4).toString()).toBe('%PDF');
  });
});
