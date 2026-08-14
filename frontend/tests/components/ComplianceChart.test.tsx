import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ComplianceChart } from '../../src/components/ComplianceChart';
import type { Finding } from '../../src/types/api';

const FINDINGS: Finding[] = [
  { type: 'compliance_violation', severity: 'critical', rule_id: 'r1', description: 'a', recommendation: 'x' },
  { type: 'compliance_violation', severity: 'high', rule_id: 'r2', description: 'b', recommendation: 'y' },
  { type: 'conflict', severity: 'medium', rule_id: 'r3', description: 'c', recommendation: 'z' },
];

describe('ComplianceChart', () => {
  it('shows a message when there are no compliance violations', () => {
    render(<ComplianceChart findings={[]} />);
    expect(screen.getByText(/no compliance violations/i)).toBeInTheDocument();
  });

  it('renders a chart when compliance violations exist', () => {
    const { container } = render(<ComplianceChart findings={FINDINGS} />);
    expect(container.querySelector('.recharts-wrapper')).not.toBeNull();
  });
});
