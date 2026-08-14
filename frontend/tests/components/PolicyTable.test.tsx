import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { PolicyTable } from '../../src/components/PolicyTable';
import type { Policy } from '../../src/types/api';

const POLICIES: Policy[] = [
  {
    _id: 'p1',
    user_id: 'u1',
    name: 'firewall-a',
    description: '',
    source_type: 'firewall',
    normalized_rules: [],
    tags: [],
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
];

describe('PolicyTable', () => {
  it('renders one row per policy', () => {
    render(<PolicyTable policies={POLICIES} onSelect={vi.fn()} onDelete={vi.fn()} />);

    expect(screen.getByText('firewall-a')).toBeInTheDocument();
  });

  it('calls onSelect when a row is clicked', async () => {
    const onSelect = vi.fn();
    render(<PolicyTable policies={POLICIES} onSelect={onSelect} onDelete={vi.fn()} />);

    await userEvent.click(screen.getByText('firewall-a'));

    expect(onSelect).toHaveBeenCalledWith('p1');
  });

  it('calls onDelete when the delete button is clicked', async () => {
    const onDelete = vi.fn();
    render(<PolicyTable policies={POLICIES} onSelect={vi.fn()} onDelete={onDelete} />);

    await userEvent.click(screen.getByRole('button', { name: /delete/i }));

    expect(onDelete).toHaveBeenCalledWith('p1');
  });

  it('shows an empty state when there are no policies', () => {
    render(<PolicyTable policies={[]} onSelect={vi.fn()} onDelete={vi.fn()} />);

    expect(screen.getByText(/no policies/i)).toBeInTheDocument();
  });
});
