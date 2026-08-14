import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { LoginPage } from '../../src/pages/LoginPage';
import { useAuthStore } from '../../src/store/authStore';
import * as api from '../../src/services/api';

vi.mock('../../src/services/api');

beforeEach(() => {
  useAuthStore.setState({ token: null });
  vi.clearAllMocks();
});

describe('LoginPage', () => {
  it('logs in and stores the token on successful submit', async () => {
    vi.mocked(api.loginUser).mockResolvedValue({ token: 'abc123' });
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    );

    await userEvent.type(screen.getByLabelText(/email/i), 'user@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'password123');
    await userEvent.click(screen.getByRole('button', { name: /log in/i }));

    expect(api.loginUser).toHaveBeenCalledWith('user@example.com', 'password123');
    expect(useAuthStore.getState().token).toBe('abc123');
  });

  it('shows an error message when login fails', async () => {
    vi.mocked(api.loginUser).mockRejectedValue(new Error('Invalid email or password'));
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    );

    await userEvent.type(screen.getByLabelText(/email/i), 'user@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: /log in/i }));

    expect(await screen.findByText(/invalid email or password/i)).toBeInTheDocument();
  });
});
