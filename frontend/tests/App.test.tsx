import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, beforeEach } from 'vitest';
import App from '../src/App';
import { useAuthStore } from '../src/store/authStore';

function renderApp(initialPath: string) {
  const queryClient = new QueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialPath]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('App', () => {
  beforeEach(() => {
    useAuthStore.setState({ token: null });
  });

  it('redirects unauthenticated users to the login page', async () => {
    renderApp('/policies');

    expect(await screen.findByRole('heading', { name: /log in/i })).toBeInTheDocument();
  });

  it('renders the policies page for authenticated users', async () => {
    useAuthStore.setState({ token: 'valid-token' });
    renderApp('/policies');

    expect(await screen.findByRole('heading', { name: /policies/i })).toBeInTheDocument();
  });
});
