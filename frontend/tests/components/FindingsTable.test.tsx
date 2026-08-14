import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { FindingsTable } from '../../src/components/FindingsTable';
import type { Finding } from '../../src/types/api';

const FINDINGS: Finding[] = [
  { type: 'orphaned', severity: 'low', rule_id: 'r1', description: 'stale rule', recommendation: 'remove it' },
  { type: 'overly_permissive', severity: 'critical', rule_id: 'r2', description: 'open to the world', recommendation: 'restrict cidr' },
];

describe('FindingsTable', () => {
  it('renders one row per finding', () => {
    render(<FindingsTable findings={FINDINGS} onSelect={vi.fn()} />);

    expect(screen.getByText('stale rule')).toBeInTheDocument();
    expect(screen.getByText('open to the world')).toBeInTheDocument();
  });

  it('sorts by severity when the severity header is clicked', async () => {
    render(<FindingsTable findings={FINDINGS} onSelect={vi.fn()} />);

    await userEvent.click(screen.getByRole('columnheader', { name: /severity/i }));

    const rows = screen.getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('critical');
  });

  it('calls onSelect with the rule id when a row is clicked', async () => {
    const onSelect = vi.fn();
    render(<FindingsTable findings={FINDINGS} onSelect={onSelect} />);

    await userEvent.click(screen.getByText('stale rule'));

    expect(onSelect).toHaveBeenCalledWith('r1');
  });
});
