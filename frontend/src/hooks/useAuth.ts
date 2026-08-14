import { useAuthStore } from '../store/authStore';

export function useAuth() {
  const token = useAuthStore((state) => state.token);
  const setToken = useAuthStore((state) => state.setToken);

  return {
    token,
    isAuthenticated: token !== null,
    login: (newToken: string) => setToken(newToken),
    logout: () => setToken(null),
  };
}
