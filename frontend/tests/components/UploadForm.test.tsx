import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { ReactElement } from 'react';
import { UploadForm } from '../../src/components/UploadForm';
import { useAuthStore } from '../../src/store/authStore';
import * as api from '../../src/services/api';

vi.mock('../../src/services/api');

function renderWithClient(ui: ReactElement) {
  const queryClient = new QueryClient();
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  useAuthStore.setState({ token: 'test-token' });
  vi.clearAllMocks();
});

describe('UploadForm', () => {
  it('submits the file and metadata, then notifies on success', async () => {
    const onUploaded = vi.fn();
    vi.mocked(api.uploadPolicy).mockResolvedValue({ _id: 'p1' } as never);

    renderWithClient(<UploadForm onUploaded={onUploaded} />);

    await userEvent.type(screen.getByLabelText(/policy name/i), 'my-policy');
    const file = new File(['{"rules":[]}'], 'rules.json', { type: 'application/json' });
    await userEvent.upload(screen.getByLabelText(/file/i), file);
    await userEvent.click(screen.getByRole('button', { name: /upload/i }));

    expect(api.uploadPolicy).toHaveBeenCalledWith('test-token', expect.any(FormData));
    expect(await screen.findByText(/uploaded/i)).toBeInTheDocument();
    expect(onUploaded).toHaveBeenCalledWith({ _id: 'p1' });
  });

  it('shows an error message when upload fails', async () => {
    vi.mocked(api.uploadPolicy).mockRejectedValue(new Error('File exceeds maximum allowed size'));

    renderWithClient(<UploadForm onUploaded={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/policy name/i), 'too-big');
    const file = new File(['x'], 'rules.json', { type: 'application/json' });
    await userEvent.upload(screen.getByLabelText(/file/i), file);
    await userEvent.click(screen.getByRole('button', { name: /upload/i }));

    expect(await screen.findByText(/exceeds maximum allowed size/i)).toBeInTheDocument();
  });
});
