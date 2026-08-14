import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RiskMatrix } from '../../src/components/RiskMatrix';
import type { Finding, NormalizedRule } from '../../src/types/api';

const RULES: NormalizedRule[] = [
  {
    id: 'r1',
    source_type: 'firewall',
    source_id: 'fw-1',
    protocol: 'tcp',
    port_range: { start: 22, end: 22 },
    direction: 'ingress',
    action: 'allow',
    source: { type: 'cidr', value: '0.0.0.0/0' },
    destination: { type: 'cidr', value: '10.0.0.0/8' },
    created_at: '2026-01-01T00:00:00Z',
    modified_at: '2026-01-01T00:00:00Z',
    description: '',
    tags: {},
  },
];

const FINDINGS: Finding[] = [
  { type: 'overly_permissive', severity: 'critical', rule_id: 'r1', description: 'open', recommendation: 'fix' },
];

describe('RiskMatrix', () => {
  it('shows a message when there are no findings', () => {
    render(<RiskMatrix findings={[]} rules={RULES} />);
    expect(screen.getByText(/no findings/i)).toBeInTheDocument();
  });

  it('renders a chart when findings exist', () => {
    const { container } = render(<RiskMatrix findings={FINDINGS} rules={RULES} />);
    expect(container.querySelector('.recharts-wrapper')).not.toBeNull();
  });
});
