import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { RuleDetailPanel } from '../../src/components/RuleDetailPanel';
import type { NormalizedRule } from '../../src/types/api';

const RULE: NormalizedRule = {
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
  description: 'ssh',
  tags: {},
};

describe('RuleDetailPanel', () => {
  it('renders nothing when no rule is selected', () => {
    const { container } = render(<RuleDetailPanel rule={null} onClose={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('renders rule details when a rule is selected', () => {
    render(<RuleDetailPanel rule={RULE} onClose={vi.fn()} />);

    expect(screen.getByText('fw-1')).toBeInTheDocument();
    expect(screen.getByText(/0\.0\.0\.0\/0/)).toBeInTheDocument();
  });

  it('calls onClose when the close button is clicked', async () => {
    const onClose = vi.fn();
    render(<RuleDetailPanel rule={RULE} onClose={onClose} />);

    await userEvent.click(screen.getByRole('button', { name: /close/i }));

    expect(onClose).toHaveBeenCalled();
  });
});
