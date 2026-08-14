import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { RegisterPage } from '../../src/pages/RegisterPage';
import { useAuthStore } from '../../src/store/authStore';
import * as api from '../../src/services/api';

vi.mock('../../src/services/api');

beforeEach(() => {
  useAuthStore.setState({ token: null });
  vi.clearAllMocks();
});

describe('RegisterPage', () => {
  it('registers and stores the token on successful submit', async () => {
    vi.mocked(api.registerUser).mockResolvedValue({ token: 'xyz789' });
    render(
      <MemoryRouter>
        <RegisterPage />
      </MemoryRouter>,
    );

    await userEvent.type(screen.getByLabelText(/email/i), 'new@example.com');
    await userEvent.type(screen.getByLabelText(/^password/i), 'password123');
    await userEvent.click(screen.getByRole('button', { name: /register/i }));

    expect(api.registerUser).toHaveBeenCalledWith('new@example.com', 'password123', undefined);
    expect(useAuthStore.getState().token).toBe('xyz789');
  });

  it('shows an error message when registration fails', async () => {
    vi.mocked(api.registerUser).mockRejectedValue(new Error('Email already registered'));
    render(
      <MemoryRouter>
        <RegisterPage />
      </MemoryRouter>,
    );

    await userEvent.type(screen.getByLabelText(/email/i), 'dup@example.com');
    await userEvent.type(screen.getByLabelText(/^password/i), 'password123');
    await userEvent.click(screen.getByRole('button', { name: /register/i }));

    expect(await screen.findByText(/email already registered/i)).toBeInTheDocument();
  });
});
