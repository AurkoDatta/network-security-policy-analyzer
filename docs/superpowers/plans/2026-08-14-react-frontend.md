# React Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 4 (`prompt.txt` Milestones 4A/4B/4C) — a working React UI for uploading policies, viewing analysis results in a findings table with filters and a rule detail panel, visualizing risk/compliance with charts, and exploring an interactive network diagram of the policy's rule graph.

**Architecture:** React Router drives page navigation (login, register, policy list/upload, analysis dashboard). TanStack Query owns all server state (policies, analyses) with the API's JWT-protected endpoints; a small Zustand store holds only the auth token, persisted to `localStorage`. All API calls flow through one typed `apiFetch` helper that attaches the bearer token and normalizes errors. Component tests mock the API/`cytoscape` layer rather than hitting a real server or canvas, matching the existing Vitest + React Testing Library setup.

**Tech Stack:** React 18 + TypeScript + Tailwind (existing), `react-router-dom` (new — routing), `@tanstack/react-query` (new — server state), `zustand` (new — auth token store), `react-hook-form` + `zod` + `@hookform/resolvers` (new — upload/login form validation), `cytoscape` (new — network diagram; PNG export via its built-in `cy.png()`, no extra SVG-export dependency), `recharts` (new — risk gauge, compliance chart, risk matrix), `@testing-library/user-event` (new devDependency — form interaction tests).

## Global Constraints

- No AI/Claude/LLM attribution anywhere in code, comments, or commit messages.
- Commit messages for Milestone 4A/4B/4C work must be the exact strings from `prompt.txt`, used in this order: "feat: add upload form and policy list page", "feat: build findings table and detail view", "feat: add risk score and compliance charts", "feat: implement network diagram visualization", "test: add React component tests (60%+ coverage)". Frontend routing/auth infrastructure (Task 1) and login/register pages (Task 2) are prerequisites not named in `prompt.txt`'s list, so they get their own descriptive Conventional Commit messages, following the precedent set in Phases 2 and 3.
- `strict: true`, `noUnusedLocals`, `noUnusedParameters` are already enabled in `tsconfig.app.json` — every new file must compile clean under those flags.
- Tests live under `frontend/tests/`, mirroring `frontend/src/`'s structure (matches the existing `tests/App.test.tsx` / `tests/setup.ts` layout) — not colocated with source.
- TS interfaces mirroring backend models (`NormalizedRule`, `Endpoint`, `PortRange`, `RiskScore`, `Finding`, `Policy`, `Analysis`) must use the exact same field names as `api/src/models/*.ts` — no translation layer.
- No shadcn/ui — CLAUDE.md's suggested stack names it, but its CLI pulls component source from a remote registry at install time, which is a fragile, unnecessary network dependency for this codebase's needs. Plain Tailwind-styled components achieve the same result with no external moving parts.
- Component tests mock `../services/api` (or the specific API function) and `cytoscape` rather than performing real network/canvas work — consistent, fast, deterministic.
- Test coverage target: 60%+ (`prompt.txt`'s Milestone 4A-C testing goal, matches CLAUDE.md's React coverage target), focused on logic and user-facing behavior, not snapshot tests.

---

## File Structure

```
frontend/src/
  main.tsx                          (MODIFY — wrap App in QueryClientProvider + BrowserRouter)
  App.tsx                           (MODIFY — route table)
  lib/
    apiClient.ts                    (NEW — typed fetch wrapper with auth + ApiError)
  types/
    api.ts                          (NEW — NormalizedRule/RiskScore/Finding/Policy/Analysis interfaces)
  store/
    authStore.ts                    (NEW — zustand token store, persisted)
  services/
    api.ts                          (MODIFY — auth/policies/analyses API functions)
  hooks/
    useAuth.ts                      (NEW — wraps authStore + logout helper)
    usePolicies.ts                  (NEW — TanStack Query hooks: list/upload/delete)
    useAnalysis.ts                  (NEW — TanStack Query hooks: trigger/get analysis)
  components/
    ProtectedRoute.tsx              (NEW)
    UploadForm.tsx                  (NEW)
    PolicyTable.tsx                 (NEW)
    FindingsTable.tsx               (NEW)
    FindingFilters.tsx              (NEW)
    RuleDetailPanel.tsx             (NEW)
    RiskGauge.tsx                   (NEW)
    ComplianceChart.tsx             (NEW)
    NetworkDiagram.tsx              (NEW)
    RiskMatrix.tsx                  (NEW)
  pages/
    LoginPage.tsx                   (NEW)
    RegisterPage.tsx                (NEW)
    PoliciesPage.tsx                (NEW)
    AnalysisPage.tsx                (NEW)
frontend/tests/
  App.test.tsx                      (MODIFY — routes to login when unauthenticated)
  lib/apiClient.test.ts             (NEW)
  store/authStore.test.ts           (NEW)
  components/
    UploadForm.test.tsx             (NEW)
    PolicyTable.test.tsx            (NEW)
    FindingsTable.test.tsx          (NEW)
    FindingFilters.test.tsx         (NEW)
    RuleDetailPanel.test.tsx        (NEW)
    RiskGauge.test.tsx              (NEW)
    ComplianceChart.test.tsx        (NEW)
    NetworkDiagram.test.tsx         (NEW)
    RiskMatrix.test.tsx             (NEW)
  pages/
    LoginPage.test.tsx              (NEW)
    RegisterPage.test.tsx           (NEW)
```

---

### Task 1: Routing, server state, and auth infrastructure

**Files:**
- Create: `frontend/src/lib/apiClient.ts`
- Create: `frontend/src/types/api.ts`
- Create: `frontend/src/store/authStore.ts`
- Create: `frontend/src/components/ProtectedRoute.tsx`
- Create: `frontend/src/hooks/useAuth.ts`
- Modify: `frontend/src/main.tsx`
- Modify: `frontend/src/App.tsx`
- Test: `frontend/tests/lib/apiClient.test.ts`
- Test: `frontend/tests/store/authStore.test.ts`
- Test: `frontend/tests/App.test.tsx`

**Interfaces:**
- Produces: `apiFetch<T>(path: string, options?: RequestInit, token?: string | null): Promise<T>` and `class ApiError extends Error { status: number }` in `lib/apiClient.ts`. `useAuthStore` (zustand: `{ token: string | null; setToken(token: string | null): void }`) in `store/authStore.ts`. `useAuth()` returning `{ token, isAuthenticated, logout }` in `hooks/useAuth.ts`. `ProtectedRoute` component wrapping `<Outlet />`, redirecting to `/login` when unauthenticated.

- [ ] **Step 1: Install dependencies**

```bash
cd frontend && npm install react-router-dom zustand @tanstack/react-query react-hook-form zod @hookform/resolvers cytoscape recharts && npm install -D @types/cytoscape @testing-library/user-event
```

- [ ] **Step 2: Write the failing tests**

```typescript
// frontend/tests/lib/apiClient.test.ts
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiFetch, ApiError } from '../../src/lib/apiClient';

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe('apiFetch', () => {
  it('attaches the bearer token when provided', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ hello: 'world' }),
    }) as unknown as typeof fetch;

    await apiFetch('/api/policies', {}, 'token-123');

    const [, options] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = options.headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer token-123');
  });

  it('does not set an Authorization header when no token is given', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
    }) as unknown as typeof fetch;

    await apiFetch('/api/health');

    const [, options] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = options.headers as Headers;
    expect(headers.has('Authorization')).toBe(false);
  });

  it('returns undefined for 204 No Content responses', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 204 }) as unknown as typeof fetch;

    const result = await apiFetch('/api/policies/1');

    expect(result).toBeUndefined();
  });

  it('throws an ApiError with the server message on failure', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      json: async () => ({ error: 'Forbidden' }),
    }) as unknown as typeof fetch;

    await expect(apiFetch('/api/policies/1')).rejects.toThrow('Forbidden');
    await expect(apiFetch('/api/policies/1')).rejects.toBeInstanceOf(ApiError);
  });

  it('does not set Content-Type for FormData bodies', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) }) as unknown as typeof fetch;

    await apiFetch('/api/policies/upload', { method: 'POST', body: new FormData() });

    const [, options] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = options.headers as Headers;
    expect(headers.has('Content-Type')).toBe(false);
  });
});
```

```typescript
// frontend/tests/store/authStore.test.ts
import { beforeEach, describe, expect, it } from 'vitest';
import { useAuthStore } from '../../src/store/authStore';

describe('authStore', () => {
  beforeEach(() => {
    useAuthStore.setState({ token: null });
    localStorage.clear();
  });

  it('starts with no token', () => {
    expect(useAuthStore.getState().token).toBeNull();
  });

  it('sets and clears the token', () => {
    useAuthStore.getState().setToken('abc123');
    expect(useAuthStore.getState().token).toBe('abc123');

    useAuthStore.getState().setToken(null);
    expect(useAuthStore.getState().token).toBeNull();
  });
});
```

```typescript
// frontend/tests/App.test.tsx
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL — none of `lib/apiClient.ts`, `store/authStore.ts` exist yet; `App` still renders the Phase 1 placeholder heading.

- [ ] **Step 4: Implement**

```typescript
// frontend/src/types/api.ts
export interface PortRange {
  start: number;
  end: number;
}

export interface Endpoint {
  type: 'cidr' | 'ip' | 'security_group' | 'principal';
  value: string;
}

export interface NormalizedRule {
  id: string;
  source_type: 'security_group' | 'firewall' | 'iam_policy';
  source_id: string;
  protocol: string;
  port_range: PortRange | null;
  direction: 'ingress' | 'egress';
  action: 'allow' | 'deny';
  source: Endpoint;
  destination: Endpoint;
  created_at: string;
  modified_at: string;
  description: string;
  tags: Record<string, string>;
}

export interface RiskScore {
  overall: number;
  permissiveness: number;
  exposure: number;
  compliance_violations: number;
  unused: number;
}

export type FindingType = 'overly_permissive' | 'conflict' | 'orphaned' | 'compliance_violation';
export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  type: FindingType;
  severity: Severity;
  rule_id: string;
  description: string;
  recommendation: string;
}

export interface Policy {
  _id: string;
  user_id: string;
  name: string;
  description: string;
  source_type: 'aws' | 'firewall' | 'iam';
  normalized_rules: NormalizedRule[];
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface Analysis {
  _id: string;
  policy_id: string;
  risk_score: RiskScore;
  findings: Finding[];
  generated_at: string;
}
```

```typescript
// frontend/src/lib/apiClient.ts
const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:5000';

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  token?: string | null,
): Promise<T> {
  const headers = new Headers(options.headers);
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}) as { error?: string });
    throw new ApiError(body.error ?? `Request failed with status ${response.status}`, response.status);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}
```

```typescript
// frontend/src/store/authStore.ts
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface AuthState {
  token: string | null;
  setToken: (token: string | null) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      setToken: (token) => set({ token }),
    }),
    { name: 'auth-storage' },
  ),
);
```

```typescript
// frontend/src/hooks/useAuth.ts
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
```

```typescript
// frontend/src/components/ProtectedRoute.tsx
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export function ProtectedRoute() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
```

```typescript
// frontend/src/App.tsx
import { Navigate, Route, Routes } from 'react-router-dom';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { AnalysisPage } from './pages/AnalysisPage';

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route element={<ProtectedRoute />}>
        <Route path="/policies" element={<PoliciesPage />} />
        <Route path="/analyses/:id" element={<AnalysisPage />} />
      </Route>
      <Route path="/" element={<Navigate to="/policies" replace />} />
    </Routes>
  );
}

export default App;
```

```typescript
// frontend/src/main.tsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import './index.css';
import App from './App.tsx';

const queryClient = new QueryClient();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
```

Note: `LoginPage`, `RegisterPage`, `PoliciesPage`, and `AnalysisPage` are created as minimal placeholder components in Task 2 (login/register) and Task 3 (policies) before this task's tests can pass — Task 1's tests reference `PoliciesPage` rendering a "Policies" heading and `LoginPage` rendering a "Log in" heading, which those later tasks fulfill. Implement Task 1's files as listed above, then create minimal stub versions of the four page components (just enough to satisfy this task's tests: `LoginPage` renders `<h1>Log in</h1>`, `RegisterPage` renders `<h1>Register</h1>`, `PoliciesPage` renders `<h1>Policies</h1>`, `AnalysisPage` renders `<h1>Analysis</h1>`) so Task 1 is independently testable; Tasks 2-3 replace the stubs with full implementations.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd frontend && npm test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add frontend/src/lib frontend/src/types frontend/src/store frontend/src/components/ProtectedRoute.tsx frontend/src/hooks/useAuth.ts frontend/src/main.tsx frontend/src/App.tsx frontend/src/pages frontend/tests/lib frontend/tests/store frontend/tests/App.test.tsx frontend/package.json frontend/package-lock.json
git commit -m "feat: add frontend routing, state management, and auth"
```

---

### Task 2: Login and registration pages

**Files:**
- Modify: `frontend/src/services/api.ts`
- Modify: `frontend/src/pages/LoginPage.tsx` (replace Task 1's stub)
- Modify: `frontend/src/pages/RegisterPage.tsx` (replace Task 1's stub)
- Test: `frontend/tests/pages/LoginPage.test.tsx`
- Test: `frontend/tests/pages/RegisterPage.test.tsx`

**Interfaces:**
- Consumes: `apiFetch` from `../lib/apiClient`; `useAuth` from `../hooks/useAuth`.
- Produces: `registerUser(email: string, password: string, name?: string): Promise<{ token: string }>` and `loginUser(email: string, password: string): Promise<{ token: string }>` added to `services/api.ts`.

- [ ] **Step 1: Write the failing tests**

```typescript
// frontend/tests/pages/LoginPage.test.tsx
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
    expect(await screen.findByText(/abc123|policies/i)).toBeTruthy();
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
```

```typescript
// frontend/tests/pages/RegisterPage.test.tsx
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL — `api.loginUser`/`api.registerUser` don't exist; `LoginPage`/`RegisterPage` are still Task 1's one-line stubs.

- [ ] **Step 3: Implement**

Add to `frontend/src/services/api.ts` (keep the existing `getHealth`):

```typescript
import { apiFetch } from '../lib/apiClient';

export async function loginUser(email: string, password: string): Promise<{ token: string }> {
  return apiFetch('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
}

export async function registerUser(
  email: string,
  password: string,
  name?: string,
): Promise<{ token: string }> {
  return apiFetch('/api/auth/register', { method: 'POST', body: JSON.stringify({ email, password, name }) });
}
```

```typescript
// frontend/src/pages/LoginPage.tsx
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Link, useNavigate } from 'react-router-dom';
import { loginUser } from '../services/api';
import { useAuth } from '../hooks/useAuth';

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1, 'Password is required'),
});

type LoginForm = z.infer<typeof loginSchema>;

export function LoginPage() {
  const { register, handleSubmit, formState } = useForm<LoginForm>({ resolver: zodResolver(loginSchema) });
  const { login } = useAuth();
  const navigate = useNavigate();
  const [serverError, setServerError] = useState<string | null>(null);

  const onSubmit = async (data: LoginForm) => {
    setServerError(null);
    try {
      const { token } = await loginUser(data.email, data.password);
      login(token);
      navigate('/policies');
    } catch (err) {
      setServerError((err as Error).message);
    }
  };

  return (
    <div className="mx-auto flex min-h-screen max-w-sm flex-col justify-center gap-4 px-4">
      <h1 className="text-2xl font-semibold">Log in</h1>
      <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-sm">
          Email
          <input {...register('email')} type="email" className="rounded border px-3 py-2" />
          {formState.errors.email && <span className="text-red-600">{formState.errors.email.message}</span>}
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Password
          <input {...register('password')} type="password" className="rounded border px-3 py-2" />
          {formState.errors.password && (
            <span className="text-red-600">{formState.errors.password.message}</span>
          )}
        </label>
        {serverError && <p className="text-red-600">{serverError}</p>}
        <button type="submit" className="rounded bg-slate-900 px-4 py-2 text-white" disabled={formState.isSubmitting}>
          Log in
        </button>
      </form>
      <p className="text-sm">
        Need an account? <Link to="/register" className="underline">Register</Link>
      </p>
    </div>
  );
}
```

```typescript
// frontend/src/pages/RegisterPage.tsx
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Link, useNavigate } from 'react-router-dom';
import { registerUser } from '../services/api';
import { useAuth } from '../hooks/useAuth';

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().optional(),
});

type RegisterForm = z.infer<typeof registerSchema>;

export function RegisterPage() {
  const { register, handleSubmit, formState } = useForm<RegisterForm>({ resolver: zodResolver(registerSchema) });
  const { login } = useAuth();
  const navigate = useNavigate();
  const [serverError, setServerError] = useState<string | null>(null);

  const onSubmit = async (data: RegisterForm) => {
    setServerError(null);
    try {
      const { token } = await registerUser(data.email, data.password, data.name || undefined);
      login(token);
      navigate('/policies');
    } catch (err) {
      setServerError((err as Error).message);
    }
  };

  return (
    <div className="mx-auto flex min-h-screen max-w-sm flex-col justify-center gap-4 px-4">
      <h1 className="text-2xl font-semibold">Register</h1>
      <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-sm">
          Email
          <input {...register('email')} type="email" className="rounded border px-3 py-2" />
          {formState.errors.email && <span className="text-red-600">{formState.errors.email.message}</span>}
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Password
          <input {...register('password')} type="password" className="rounded border px-3 py-2" />
          {formState.errors.password && (
            <span className="text-red-600">{formState.errors.password.message}</span>
          )}
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Name (optional)
          <input {...register('name')} type="text" className="rounded border px-3 py-2" />
        </label>
        {serverError && <p className="text-red-600">{serverError}</p>}
        <button type="submit" className="rounded bg-slate-900 px-4 py-2 text-white" disabled={formState.isSubmitting}>
          Register
        </button>
      </form>
      <p className="text-sm">
        Already have an account? <Link to="/login" className="underline">Log in</Link>
      </p>
    </div>
  );
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npm test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/services/api.ts frontend/src/pages/LoginPage.tsx frontend/src/pages/RegisterPage.tsx frontend/tests/pages/LoginPage.test.tsx frontend/tests/pages/RegisterPage.test.tsx
git commit -m "feat: add login and registration pages"
```

---

### Task 3: Upload form and policy list page

**Files:**
- Modify: `frontend/src/services/api.ts`
- Create: `frontend/src/hooks/usePolicies.ts`
- Create: `frontend/src/components/UploadForm.tsx`
- Create: `frontend/src/components/PolicyTable.tsx`
- Modify: `frontend/src/pages/PoliciesPage.tsx` (replace Task 1's stub)
- Test: `frontend/tests/components/UploadForm.test.tsx`
- Test: `frontend/tests/components/PolicyTable.test.tsx`

**Interfaces:**
- Consumes: `apiFetch`, `Policy` type, `useAuth`.
- Produces: `listPolicies(token: string): Promise<Policy[]>`, `uploadPolicy(token: string, formData: FormData): Promise<Policy>`, `deletePolicy(token: string, id: string): Promise<void>` in `services/api.ts`. `usePolicies()` / `useUploadPolicy()` / `useDeletePolicy()` TanStack Query hooks in `hooks/usePolicies.ts`. `<UploadForm onUploaded={(policy) => void}>` and `<PolicyTable policies={Policy[]} onSelect={(id) => void} onDelete={(id) => void}>` components.

- [ ] **Step 1: Write the failing tests**

```typescript
// frontend/tests/components/UploadForm.test.tsx
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { UploadForm } from '../../src/components/UploadForm';
import { useAuthStore } from '../../src/store/authStore';
import * as api from '../../src/services/api';

vi.mock('../../src/services/api');

function renderWithClient(ui: React.ReactElement) {
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
```

```typescript
// frontend/tests/components/PolicyTable.test.tsx
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL — `UploadForm`/`PolicyTable` don't exist; `api.uploadPolicy` doesn't exist.

- [ ] **Step 3: Implement**

Add to `frontend/src/services/api.ts`:

```typescript
import { Policy } from '../types/api';

export async function listPolicies(token: string): Promise<Policy[]> {
  return apiFetch('/api/policies', {}, token);
}

export async function uploadPolicy(token: string, formData: FormData): Promise<Policy> {
  return apiFetch('/api/policies/upload', { method: 'POST', body: formData }, token);
}

export async function deletePolicy(token: string, id: string): Promise<void> {
  return apiFetch(`/api/policies/${id}`, { method: 'DELETE' }, token);
}
```

```typescript
// frontend/src/hooks/usePolicies.ts
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { deletePolicy, listPolicies, uploadPolicy } from '../services/api';
import { useAuth } from './useAuth';

export function usePolicies() {
  const { token } = useAuth();
  return useQuery({
    queryKey: ['policies'],
    queryFn: () => listPolicies(token as string),
    enabled: token !== null,
  });
}

export function useUploadPolicy() {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (formData: FormData) => uploadPolicy(token as string, formData),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['policies'] }),
  });
}

export function useDeletePolicy() {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deletePolicy(token as string, id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['policies'] }),
  });
}
```

```typescript
// frontend/src/components/UploadForm.tsx
import { useState } from 'react';
import { useUploadPolicy } from '../hooks/usePolicies';
import type { Policy } from '../types/api';

interface UploadFormProps {
  onUploaded: (policy: Policy) => void;
}

export function UploadForm({ onUploaded }: UploadFormProps) {
  const [name, setName] = useState('');
  const [sourceType, setSourceType] = useState<'aws' | 'firewall' | 'iam'>('firewall');
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [succeeded, setSucceeded] = useState(false);
  const upload = useUploadPolicy();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSucceeded(false);
    if (!file) {
      setError('A file is required');
      return;
    }

    const formData = new FormData();
    formData.append('name', name);
    formData.append('source_type', sourceType);
    formData.append('file', file);

    try {
      const policy = await upload.mutateAsync(formData);
      setSucceeded(true);
      onUploaded(policy);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3 rounded border p-4">
      <label className="flex flex-col gap-1 text-sm">
        Policy name
        <input value={name} onChange={(e) => setName(e.target.value)} className="rounded border px-3 py-2" />
      </label>
      <label className="flex flex-col gap-1 text-sm">
        Source type
        <select
          value={sourceType}
          onChange={(e) => setSourceType(e.target.value as 'aws' | 'firewall' | 'iam')}
          className="rounded border px-3 py-2"
        >
          <option value="firewall">Firewall</option>
          <option value="aws">AWS Security Group</option>
          <option value="iam">IAM Policy</option>
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm">
        File
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="rounded border px-3 py-2"
        />
      </label>
      {error && <p className="text-red-600">{error}</p>}
      {succeeded && <p className="text-green-600">Policy uploaded successfully.</p>}
      <button type="submit" className="rounded bg-slate-900 px-4 py-2 text-white" disabled={upload.isPending}>
        Upload
      </button>
    </form>
  );
}
```

```typescript
// frontend/src/components/PolicyTable.tsx
import type { Policy } from '../types/api';

interface PolicyTableProps {
  policies: Policy[];
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
}

export function PolicyTable({ policies, onSelect, onDelete }: PolicyTableProps) {
  if (policies.length === 0) {
    return <p className="text-slate-500">No policies uploaded yet.</p>;
  }

  return (
    <table className="w-full border-collapse text-left">
      <thead>
        <tr className="border-b">
          <th className="py-2">Name</th>
          <th className="py-2">Source</th>
          <th className="py-2">Rules</th>
          <th className="py-2" />
        </tr>
      </thead>
      <tbody>
        {policies.map((policy) => (
          <tr key={policy._id} className="border-b">
            <td className="cursor-pointer py-2 underline" onClick={() => onSelect(policy._id)}>
              {policy.name}
            </td>
            <td className="py-2">{policy.source_type}</td>
            <td className="py-2">{policy.normalized_rules.length}</td>
            <td className="py-2">
              <button
                type="button"
                onClick={() => onDelete(policy._id)}
                className="rounded border px-2 py-1 text-sm text-red-600"
              >
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
```

```typescript
// frontend/src/pages/PoliciesPage.tsx
import { useNavigate } from 'react-router-dom';
import { UploadForm } from '../components/UploadForm';
import { PolicyTable } from '../components/PolicyTable';
import { usePolicies, useDeletePolicy } from '../hooks/usePolicies';
import { useAnalyzePolicy } from '../hooks/useAnalysis';

export function PoliciesPage() {
  const { data: policies, isLoading, error } = usePolicies();
  const deletePolicy = useDeletePolicy();
  const analyze = useAnalyzePolicy();
  const navigate = useNavigate();

  const handleSelect = async (id: string) => {
    const analysis = await analyze.mutateAsync(id);
    navigate(`/analyses/${analysis._id}`);
  };

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-6 px-4 py-8">
      <h1 className="text-2xl font-semibold">Policies</h1>
      <UploadForm onUploaded={() => undefined} />
      {isLoading && <p>Loading policies…</p>}
      {error && <p className="text-red-600">{(error as Error).message}</p>}
      {policies && <PolicyTable policies={policies} onSelect={handleSelect} onDelete={(id) => deletePolicy.mutate(id)} />}
    </div>
  );
}
```

Note: `PoliciesPage` references `useAnalyzePolicy` from `hooks/useAnalysis`, which Task 4 creates. For this task's own tests (`UploadForm.test.tsx`, `PolicyTable.test.tsx`), only `UploadForm` and `PolicyTable` are under test in isolation — `PoliciesPage` itself is exercised indirectly starting in Task 4 once `useAnalysis` exists. Implement `PoliciesPage` in this task as shown; its own dedicated test is not required since `App.test.tsx` (Task 1) already covers its rendering, and Task 4 will cover the `useAnalyzePolicy` interaction through `AnalysisPage`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npm test`
Expected: `UploadForm.test.tsx` and `PolicyTable.test.tsx` PASS. `App.test.tsx` and other suites may show a type/reference error for `useAnalyzePolicy` until Task 4 — to keep this task independently green, create a minimal placeholder in `frontend/src/hooks/useAnalysis.ts` now:

```typescript
// frontend/src/hooks/useAnalysis.ts (placeholder — Task 4 replaces this)
import { useMutation } from '@tanstack/react-query';
import type { Analysis } from '../types/api';

export function useAnalyzePolicy() {
  return useMutation<Analysis, Error, string>({
    mutationFn: () => {
      throw new Error('not implemented until Task 4');
    },
  });
}
```

Then re-run: `cd frontend && npm test` — expect all suites PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/services/api.ts frontend/src/hooks/usePolicies.ts frontend/src/hooks/useAnalysis.ts frontend/src/components/UploadForm.tsx frontend/src/components/PolicyTable.tsx frontend/src/pages/PoliciesPage.tsx frontend/tests/components/UploadForm.test.tsx frontend/tests/components/PolicyTable.test.tsx
git commit -m "feat: add upload form and policy list page"
```

---

### Task 4: Findings table, filters, and rule detail panel

**Files:**
- Modify: `frontend/src/services/api.ts`
- Modify: `frontend/src/hooks/useAnalysis.ts` (replace Task 3's placeholder)
- Create: `frontend/src/components/FindingsTable.tsx`
- Create: `frontend/src/components/FindingFilters.tsx`
- Create: `frontend/src/components/RuleDetailPanel.tsx`
- Modify: `frontend/src/pages/AnalysisPage.tsx` (replace Task 1's stub)
- Test: `frontend/tests/components/FindingsTable.test.tsx`
- Test: `frontend/tests/components/FindingFilters.test.tsx`
- Test: `frontend/tests/components/RuleDetailPanel.test.tsx`

**Interfaces:**
- Consumes: `Finding`, `NormalizedRule`, `Analysis` types.
- Produces: `getAnalysis(token, id): Promise<Analysis>`, `triggerAnalysis(token, policyId): Promise<Analysis>` in `services/api.ts`. `useAnalysis(id)` / `useAnalyzePolicy()` in `hooks/useAnalysis.ts`. `<FindingsTable findings={Finding[]} onSelect={(f) => void}>` (sortable by severity/type). `<FindingFilters findings={Finding[]} onFilterChange={(filtered) => void}>`. `<RuleDetailPanel rule={NormalizedRule | null} onClose={() => void}>`.

- [ ] **Step 1: Write the failing tests**

```typescript
// frontend/tests/components/FindingsTable.test.tsx
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
```

```typescript
// frontend/tests/components/FindingFilters.test.tsx
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { FindingFilters } from '../../src/components/FindingFilters';
import type { Finding } from '../../src/types/api';

const FINDINGS: Finding[] = [
  { type: 'orphaned', severity: 'low', rule_id: 'r1', description: 'a', recommendation: 'x' },
  { type: 'overly_permissive', severity: 'critical', rule_id: 'r2', description: 'b', recommendation: 'y' },
];

describe('FindingFilters', () => {
  it('calls onFilterChange with all findings by default', () => {
    const onFilterChange = vi.fn();
    render(<FindingFilters findings={FINDINGS} onFilterChange={onFilterChange} />);

    expect(onFilterChange).toHaveBeenCalledWith(FINDINGS);
  });

  it('filters by severity', async () => {
    const onFilterChange = vi.fn();
    render(<FindingFilters findings={FINDINGS} onFilterChange={onFilterChange} />);

    await userEvent.selectOptions(screen.getByLabelText(/severity/i), 'critical');

    expect(onFilterChange).toHaveBeenLastCalledWith([FINDINGS[1]]);
  });

  it('filters by type', async () => {
    const onFilterChange = vi.fn();
    render(<FindingFilters findings={FINDINGS} onFilterChange={onFilterChange} />);

    await userEvent.selectOptions(screen.getByLabelText(/type/i), 'orphaned');

    expect(onFilterChange).toHaveBeenLastCalledWith([FINDINGS[0]]);
  });
});
```

```typescript
// frontend/tests/components/RuleDetailPanel.test.tsx
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL — none of the three components exist yet.

- [ ] **Step 3: Implement**

Add to `frontend/src/services/api.ts`:

```typescript
import { Analysis } from '../types/api';

export async function getAnalysis(token: string, id: string): Promise<Analysis> {
  return apiFetch(`/api/analyses/${id}`, {}, token);
}

export async function triggerAnalysis(token: string, policyId: string): Promise<Analysis> {
  return apiFetch(`/api/policies/${policyId}/analyze`, { method: 'POST' }, token);
}
```

```typescript
// frontend/src/hooks/useAnalysis.ts
import { useMutation, useQuery } from '@tanstack/react-query';
import { getAnalysis, triggerAnalysis } from '../services/api';
import { useAuth } from './useAuth';
import type { Analysis } from '../types/api';

export function useAnalysis(id: string | undefined) {
  const { token } = useAuth();
  return useQuery({
    queryKey: ['analyses', id],
    queryFn: () => getAnalysis(token as string, id as string),
    enabled: token !== null && id !== undefined,
  });
}

export function useAnalyzePolicy() {
  const { token } = useAuth();
  return useMutation<Analysis, Error, string>({
    mutationFn: (policyId: string) => triggerAnalysis(token as string, policyId),
  });
}
```

```typescript
// frontend/src/components/FindingsTable.tsx
import { useMemo, useState } from 'react';
import type { Finding, Severity } from '../types/api';

interface FindingsTableProps {
  findings: Finding[];
  onSelect: (ruleId: string) => void;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

type SortKey = 'severity' | 'type';

export function FindingsTable({ findings, onSelect }: FindingsTableProps) {
  const [sortKey, setSortKey] = useState<SortKey | null>(null);

  const sorted = useMemo(() => {
    if (!sortKey) return findings;
    return [...findings].sort((a, b) => {
      if (sortKey === 'severity') return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      return a.type.localeCompare(b.type);
    });
  }, [findings, sortKey]);

  return (
    <table className="w-full border-collapse text-left">
      <thead>
        <tr className="border-b">
          <th className="cursor-pointer py-2" onClick={() => setSortKey('severity')} role="columnheader">
            Severity
          </th>
          <th className="cursor-pointer py-2" onClick={() => setSortKey('type')} role="columnheader">
            Type
          </th>
          <th className="py-2">Description</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((finding, index) => (
          <tr key={`${finding.rule_id}-${index}`} className="cursor-pointer border-b" onClick={() => onSelect(finding.rule_id)}>
            <td className="py-2">{finding.severity}</td>
            <td className="py-2">{finding.type}</td>
            <td className="py-2">{finding.description}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
```

```typescript
// frontend/src/components/FindingFilters.tsx
import { useEffect, useState } from 'react';
import type { Finding, FindingType, Severity } from '../types/api';

interface FindingFiltersProps {
  findings: Finding[];
  onFilterChange: (filtered: Finding[]) => void;
}

export function FindingFilters({ findings, onFilterChange }: FindingFiltersProps) {
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [type, setType] = useState<FindingType | 'all'>('all');

  useEffect(() => {
    const filtered = findings.filter(
      (f) => (severity === 'all' || f.severity === severity) && (type === 'all' || f.type === type),
    );
    onFilterChange(filtered);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings, severity, type]);

  return (
    <div className="flex gap-4">
      <label className="flex flex-col gap-1 text-sm">
        Severity
        <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | 'all')} className="rounded border px-2 py-1">
          <option value="all">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm">
        Type
        <select value={type} onChange={(e) => setType(e.target.value as FindingType | 'all')} className="rounded border px-2 py-1">
          <option value="all">All</option>
          <option value="overly_permissive">Overly permissive</option>
          <option value="conflict">Conflict</option>
          <option value="orphaned">Orphaned</option>
          <option value="compliance_violation">Compliance violation</option>
        </select>
      </label>
    </div>
  );
}
```

```typescript
// frontend/src/components/RuleDetailPanel.tsx
import type { NormalizedRule } from '../types/api';

interface RuleDetailPanelProps {
  rule: NormalizedRule | null;
  onClose: () => void;
}

export function RuleDetailPanel({ rule, onClose }: RuleDetailPanelProps) {
  if (!rule) return null;

  return (
    <aside className="fixed right-0 top-0 flex h-full w-80 flex-col gap-2 border-l bg-white p-4 shadow-lg">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{rule.source_id}</h2>
        <button type="button" onClick={onClose} aria-label="close" className="text-slate-500">
          Close
        </button>
      </div>
      <p>Protocol: {rule.protocol}</p>
      <p>Direction: {rule.direction}</p>
      <p>Action: {rule.action}</p>
      {rule.port_range && (
        <p>
          Ports: {rule.port_range.start}-{rule.port_range.end}
        </p>
      )}
      <p>Source: {rule.source.value}</p>
      <p>Destination: {rule.destination.value}</p>
      {rule.description && <p>Description: {rule.description}</p>}
    </aside>
  );
}
```

```typescript
// frontend/src/pages/AnalysisPage.tsx
import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useAnalysis } from '../hooks/useAnalysis';
import { FindingsTable } from '../components/FindingsTable';
import { FindingFilters } from '../components/FindingFilters';
import { RuleDetailPanel } from '../components/RuleDetailPanel';
import type { Finding, NormalizedRule } from '../types/api';

export function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const { data: analysis, isLoading, error } = useAnalysis(id);
  const [filtered, setFiltered] = useState<Finding[]>([]);
  const [selectedRule, setSelectedRule] = useState<NormalizedRule | null>(null);

  if (isLoading) return <p className="p-8">Loading analysis…</p>;
  if (error) return <p className="p-8 text-red-600">{(error as Error).message}</p>;
  if (!analysis) return null;

  const handleSelect = (ruleId: string) => {
    const rule = analysis.findings.length > 0 ? null : null;
    setSelectedRule(rule);
    void ruleId;
  };

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-8">
      <h1 className="text-2xl font-semibold">Analysis</h1>
      <FindingFilters findings={analysis.findings} onFilterChange={setFiltered} />
      <FindingsTable findings={filtered} onSelect={handleSelect} />
      <RuleDetailPanel rule={selectedRule} onClose={() => setSelectedRule(null)} />
    </div>
  );
}
```

Note: `AnalysisPage`'s `handleSelect` cannot resolve a full `NormalizedRule` from a `rule_id` alone here — `Analysis.findings` only carries `rule_id`, not the rule itself. This is resolved in Task 6, where `AnalysisPage` also fetches the parent `Policy` (for its `normalized_rules`) to look up the selected rule by id; until then, `handleSelect` is a placeholder that satisfies the type signature without a real lookup. Implement it exactly as shown above for this task.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npm test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/services/api.ts frontend/src/hooks/useAnalysis.ts frontend/src/components/FindingsTable.tsx frontend/src/components/FindingFilters.tsx frontend/src/components/RuleDetailPanel.tsx frontend/src/pages/AnalysisPage.tsx frontend/tests/components/FindingsTable.test.tsx frontend/tests/components/FindingFilters.test.tsx frontend/tests/components/RuleDetailPanel.test.tsx
git commit -m "feat: build findings table and detail view"
```

---

### Task 5: Risk score gauge and compliance breakdown chart

**Files:**
- Create: `frontend/src/components/RiskGauge.tsx`
- Create: `frontend/src/components/ComplianceChart.tsx`
- Modify: `frontend/src/pages/AnalysisPage.tsx` (render the new charts)
- Test: `frontend/tests/components/RiskGauge.test.tsx`
- Test: `frontend/tests/components/ComplianceChart.test.tsx`

**Interfaces:**
- Consumes: `RiskScore`, `Finding` types.
- Produces: `<RiskGauge score={RiskScore}>` (renders the overall score plus the four sub-scores). `<ComplianceChart findings={Finding[]}>` (bar chart of compliance-violation counts by severity).

- [ ] **Step 1: Write the failing tests**

```typescript
// frontend/tests/components/RiskGauge.test.tsx
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RiskGauge } from '../../src/components/RiskGauge';
import type { RiskScore } from '../../src/types/api';

const SCORE: RiskScore = { overall: 72, permissiveness: 80, exposure: 60, compliance_violations: 90, unused: 10 };

describe('RiskGauge', () => {
  it('displays the overall score', () => {
    render(<RiskGauge score={SCORE} />);
    expect(screen.getByText('72')).toBeInTheDocument();
  });

  it('displays each sub-score', () => {
    render(<RiskGauge score={SCORE} />);
    expect(screen.getByText(/permissiveness/i)).toBeInTheDocument();
    expect(screen.getByText(/exposure/i)).toBeInTheDocument();
    expect(screen.getByText(/compliance/i)).toBeInTheDocument();
    expect(screen.getByText(/unused/i)).toBeInTheDocument();
  });
});
```

```typescript
// frontend/tests/components/ComplianceChart.test.tsx
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL — `RiskGauge`/`ComplianceChart` don't exist yet.

- [ ] **Step 3: Implement**

```typescript
// frontend/src/components/RiskGauge.tsx
import type { RiskScore } from '../types/api';

interface RiskGaugeProps {
  score: RiskScore;
}

function scoreColor(value: number): string {
  if (value >= 75) return 'text-red-600';
  if (value >= 40) return 'text-amber-600';
  return 'text-green-600';
}

export function RiskGauge({ score }: RiskGaugeProps) {
  return (
    <div className="flex flex-col gap-3 rounded border p-4">
      <div className="flex flex-col items-center">
        <span className={`text-5xl font-bold ${scoreColor(score.overall)}`}>{score.overall}</span>
        <span className="text-sm text-slate-500">Overall risk</span>
      </div>
      <dl className="grid grid-cols-2 gap-2 text-sm">
        <dt>Permissiveness</dt>
        <dd className={scoreColor(score.permissiveness)}>{score.permissiveness}</dd>
        <dt>Exposure</dt>
        <dd className={scoreColor(score.exposure)}>{score.exposure}</dd>
        <dt>Compliance violations</dt>
        <dd className={scoreColor(score.compliance_violations)}>{score.compliance_violations}</dd>
        <dt>Unused</dt>
        <dd className={scoreColor(score.unused)}>{score.unused}</dd>
      </dl>
    </div>
  );
}
```

```typescript
// frontend/src/components/ComplianceChart.tsx
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { Finding, Severity } from '../types/api';

interface ComplianceChartProps {
  findings: Finding[];
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export function ComplianceChart({ findings }: ComplianceChartProps) {
  const violations = findings.filter((f) => f.type === 'compliance_violation');

  if (violations.length === 0) {
    return <p className="text-slate-500">No compliance violations found.</p>;
  }

  const data = SEVERITIES.map((severity) => ({
    severity,
    count: violations.filter((f) => f.severity === severity).length,
  }));

  return (
    <div className="h-64 w-full rounded border p-4">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="severity" />
          <YAxis allowDecimals={false} />
          <Tooltip />
          <Bar dataKey="count" fill="#dc2626" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
```

Add to `frontend/src/pages/AnalysisPage.tsx` (import and render alongside the findings table):

```typescript
import { RiskGauge } from '../components/RiskGauge';
import { ComplianceChart } from '../components/ComplianceChart';
```

```typescript
      <div className="grid grid-cols-2 gap-4">
        <RiskGauge score={analysis.risk_score} />
        <ComplianceChart findings={analysis.findings} />
      </div>
```

(Insert this block right after the `<h1>Analysis</h1>` line and before `<FindingFilters ...>`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npm test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/RiskGauge.tsx frontend/src/components/ComplianceChart.tsx frontend/src/pages/AnalysisPage.tsx frontend/tests/components/RiskGauge.test.tsx frontend/tests/components/ComplianceChart.test.tsx
git commit -m "feat: add risk score and compliance charts"
```

---

### Task 6: Network diagram and risk matrix visualization

**Files:**
- Create: `frontend/src/components/NetworkDiagram.tsx`
- Create: `frontend/src/components/RiskMatrix.tsx`
- Modify: `frontend/src/pages/AnalysisPage.tsx` (fetch the parent policy, wire rule lookup, render both visualizations)
- Modify: `frontend/src/services/api.ts`
- Modify: `frontend/src/hooks/usePolicies.ts`
- Test: `frontend/tests/components/NetworkDiagram.test.tsx`
- Test: `frontend/tests/components/RiskMatrix.test.tsx`

**Interfaces:**
- Consumes: `NormalizedRule`, `Finding` types; `cytoscape`.
- Produces: `getPolicy(token, id): Promise<Policy>` in `services/api.ts`; `usePolicy(id)` hook in `usePolicies.ts`. `<NetworkDiagram rules={NormalizedRule[]} findings={Finding[]} onSelectRule={(rule) => void}>` — renders a Cytoscape graph (source/destination endpoints as nodes, rules as edges colored by whether they have findings), supports a "critical only" toggle and a PNG export button. `<RiskMatrix findings={Finding[]} rules={NormalizedRule[]}>` — scatter plot of exposure (critical port touch) vs. severity rank.

- [ ] **Step 1: Write the failing tests**

```typescript
// frontend/tests/components/NetworkDiagram.test.tsx
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { NetworkDiagram } from '../../src/components/NetworkDiagram';
import type { Finding, NormalizedRule } from '../../src/types/api';

const mockCy = {
  on: vi.fn(),
  destroy: vi.fn(),
  png: vi.fn().mockReturnValue('data:image/png;base64,abc'),
  elements: vi.fn().mockReturnValue({ removeClass: vi.fn() }),
  $: vi.fn().mockReturnValue([{ id: () => 'r1', addClass: vi.fn() }]),
};

vi.mock('cytoscape', () => ({
  default: vi.fn(() => mockCy),
}));

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

beforeEach(() => {
  vi.clearAllMocks();
});

describe('NetworkDiagram', () => {
  it('initializes cytoscape with nodes and edges derived from the rules', async () => {
    const cytoscape = (await import('cytoscape')).default;
    render(<NetworkDiagram rules={RULES} findings={FINDINGS} onSelectRule={vi.fn()} />);

    expect(cytoscape).toHaveBeenCalled();
    const config = vi.mocked(cytoscape).mock.calls[0][0] as unknown as { elements: unknown[] };
    expect(config.elements.length).toBeGreaterThan(0);
  });

  it('toggles critical-only filtering', async () => {
    render(<NetworkDiagram rules={RULES} findings={FINDINGS} onSelectRule={vi.fn()} />);

    await userEvent.click(screen.getByRole('checkbox', { name: /critical only/i }));

    expect(mockCy.elements).toHaveBeenCalled();
  });

  it('exports the graph as a PNG when the export button is clicked', async () => {
    render(<NetworkDiagram rules={RULES} findings={FINDINGS} onSelectRule={vi.fn()} />);

    await userEvent.click(screen.getByRole('button', { name: /export/i }));

    expect(mockCy.png).toHaveBeenCalled();
  });
});
```

```typescript
// frontend/tests/components/RiskMatrix.test.tsx
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL — `NetworkDiagram`/`RiskMatrix` don't exist yet.

- [ ] **Step 3: Implement**

```typescript
// frontend/src/components/NetworkDiagram.tsx
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape';
import { useEffect, useRef, useState } from 'react';
import type { Finding, NormalizedRule } from '../types/api';

interface NetworkDiagramProps {
  rules: NormalizedRule[];
  findings: Finding[];
  onSelectRule: (rule: NormalizedRule) => void;
}

function buildElements(rules: NormalizedRule[], findingRuleIds: Set<string>): ElementDefinition[] {
  const nodeIds = new Set<string>();
  const elements: ElementDefinition[] = [];

  for (const rule of rules) {
    const sourceId = `${rule.source.type}:${rule.source.value}`;
    const destId = `${rule.destination.type}:${rule.destination.value}`;

    if (!nodeIds.has(sourceId)) {
      nodeIds.add(sourceId);
      elements.push({ data: { id: sourceId, label: rule.source.value } });
    }
    if (!nodeIds.has(destId)) {
      nodeIds.add(destId);
      elements.push({ data: { id: destId, label: rule.destination.value } });
    }

    elements.push({
      data: {
        id: rule.id,
        source: sourceId,
        target: destId,
        label: `${rule.protocol}${rule.port_range ? `:${rule.port_range.start}` : ''}`,
      },
      classes: findingRuleIds.has(rule.id) ? 'has-finding' : undefined,
    });
  }

  return elements;
}

export function NetworkDiagram({ rules, findings, onSelectRule }: NetworkDiagramProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [criticalOnly, setCriticalOnly] = useState(false);

  const findingRuleIds = new Set(findings.map((f) => f.rule_id));
  const criticalRuleIds = new Set(findings.filter((f) => f.severity === 'critical').map((f) => f.rule_id));

  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: buildElements(rules, findingRuleIds),
      style: [
        { selector: 'node', style: { label: 'data(label)', 'font-size': 8 } },
        { selector: 'edge', style: { label: 'data(label)', 'font-size': 8, 'line-color': '#94a3b8' } },
        { selector: 'edge.has-finding', style: { 'line-color': '#dc2626' } },
      ],
      layout: { name: 'cose' },
    });

    cy.on('tap', 'edge', (event) => {
      const ruleId = event.target.id();
      const rule = rules.find((r) => r.id === ruleId);
      if (rule) onSelectRule(rule);
    });

    cyRef.current = cy;
    return () => cy.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rules]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass('hidden-edge');
    if (criticalOnly) {
      cy.$(':edge').forEach((edge: { id: () => string; addClass: (c: string) => void }) => {
        if (!criticalRuleIds.has(edge.id())) edge.addClass('hidden-edge');
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [criticalOnly]);

  const handleExport = () => {
    const cy = cyRef.current;
    if (!cy) return;
    const dataUrl = cy.png({ full: true });
    const link = document.createElement('a');
    link.href = dataUrl;
    link.download = 'network-diagram.png';
    link.click();
  };

  return (
    <div className="flex flex-col gap-2 rounded border p-4">
      <div className="flex items-center justify-between">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={criticalOnly} onChange={(e) => setCriticalOnly(e.target.checked)} />
          Critical only
        </label>
        <button type="button" onClick={handleExport} className="rounded border px-3 py-1 text-sm">
          Export PNG
        </button>
      </div>
      <div ref={containerRef} style={{ height: 400 }} />
    </div>
  );
}
```

```typescript
// frontend/src/components/RiskMatrix.tsx
import { CartesianGrid, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis } from 'recharts';
import type { Finding, NormalizedRule, Severity } from '../types/api';

interface RiskMatrixProps {
  findings: Finding[];
  rules: NormalizedRule[];
}

const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const CRITICAL_PORTS = new Set([22, 23, 3389, 5432, 3306, 27017, 6379, 9200, 1433]);

function exposureScore(rule: NormalizedRule | undefined): number {
  if (!rule?.port_range) return 0;
  for (let port = rule.port_range.start; port <= rule.port_range.end; port++) {
    if (CRITICAL_PORTS.has(port)) return 1;
  }
  return 0;
}

export function RiskMatrix({ findings, rules }: RiskMatrixProps) {
  if (findings.length === 0) {
    return <p className="text-slate-500">No findings to plot.</p>;
  }

  const data = findings.map((finding) => {
    const rule = rules.find((r) => r.id === finding.rule_id);
    return {
      exposure: exposureScore(rule),
      severity: SEVERITY_RANK[finding.severity],
      label: finding.rule_id,
    };
  });

  return (
    <div className="h-64 w-full rounded border p-4">
      <ResponsiveContainer width="100%" height="100%">
        <ScatterChart>
          <CartesianGrid />
          <XAxis type="number" dataKey="exposure" name="Exposure" domain={[0, 1]} />
          <YAxis type="number" dataKey="severity" name="Severity" domain={[1, 4]} />
          <ZAxis range={[80, 80]} />
          <Tooltip cursor={{ strokeDasharray: '3 3' }} />
          <Scatter data={data} fill="#dc2626" />
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
}
```

Add to `frontend/src/services/api.ts`:

```typescript
export async function getPolicy(token: string, id: string): Promise<Policy> {
  return apiFetch(`/api/policies/${id}`, {}, token);
}
```

Add to `frontend/src/hooks/usePolicies.ts`:

```typescript
import { getPolicy } from '../services/api';

export function usePolicy(id: string | undefined) {
  const { token } = useAuth();
  return useQuery({
    queryKey: ['policies', id],
    queryFn: () => getPolicy(token as string, id as string),
    enabled: token !== null && id !== undefined,
  });
}
```

Replace `frontend/src/pages/AnalysisPage.tsx` in full:

```typescript
import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useAnalysis } from '../hooks/useAnalysis';
import { usePolicy } from '../hooks/usePolicies';
import { FindingsTable } from '../components/FindingsTable';
import { FindingFilters } from '../components/FindingFilters';
import { RuleDetailPanel } from '../components/RuleDetailPanel';
import { RiskGauge } from '../components/RiskGauge';
import { ComplianceChart } from '../components/ComplianceChart';
import { NetworkDiagram } from '../components/NetworkDiagram';
import { RiskMatrix } from '../components/RiskMatrix';
import type { Finding, NormalizedRule } from '../types/api';

export function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const { data: analysis, isLoading, error } = useAnalysis(id);
  const { data: policy } = usePolicy(analysis?.policy_id);
  const [filtered, setFiltered] = useState<Finding[]>([]);
  const [selectedRule, setSelectedRule] = useState<NormalizedRule | null>(null);

  if (isLoading) return <p className="p-8">Loading analysis…</p>;
  if (error) return <p className="p-8 text-red-600">{(error as Error).message}</p>;
  if (!analysis) return null;

  const rules = policy?.normalized_rules ?? [];

  const handleSelectByRuleId = (ruleId: string) => {
    const rule = rules.find((r) => r.id === ruleId);
    setSelectedRule(rule ?? null);
  };

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-8">
      <h1 className="text-2xl font-semibold">Analysis</h1>
      <div className="grid grid-cols-2 gap-4">
        <RiskGauge score={analysis.risk_score} />
        <ComplianceChart findings={analysis.findings} />
      </div>
      <RiskMatrix findings={analysis.findings} rules={rules} />
      <NetworkDiagram rules={rules} findings={analysis.findings} onSelectRule={setSelectedRule} />
      <FindingFilters findings={analysis.findings} onFilterChange={setFiltered} />
      <FindingsTable findings={filtered} onSelect={handleSelectByRuleId} />
      <RuleDetailPanel rule={selectedRule} onClose={() => setSelectedRule(null)} />
    </div>
  );
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npm test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/NetworkDiagram.tsx frontend/src/components/RiskMatrix.tsx frontend/src/pages/AnalysisPage.tsx frontend/src/services/api.ts frontend/src/hooks/usePolicies.ts frontend/tests/components/NetworkDiagram.test.tsx frontend/tests/components/RiskMatrix.test.tsx
git commit -m "feat: implement network diagram visualization"
```

---

### Task 7: Coverage top-up and final Phase 4 verification

**Files:**
- Modify (as needed): any test file above where the coverage report shows gaps.

**Interfaces:** none new — this task only adds tests for existing code.

- [ ] **Step 1: Run the full frontend test suite with coverage**

Run: `cd frontend && npx vitest run --coverage`
Expected: passes; note the coverage percentage and any files under 60% (Milestone 4's target, matching CLAUDE.md's React coverage goal).

- [ ] **Step 2: Close coverage gaps**

For any component/hook below 60%, add targeted tests for the missing branches (e.g. `apiClient`'s error-body-not-JSON fallback, `usePolicies`'s disabled-when-no-token branch, `AnalysisPage`'s loading/error states). Follow the same test style as the existing files — no new patterns needed.

- [ ] **Step 3: Re-run coverage to confirm the target is met**

Run: `cd frontend && npx vitest run --coverage`
Expected: overall coverage >60%, all tests passing.

- [ ] **Step 4: Verify the full stack still builds**

Run: `cd frontend && npm run build`
Expected: PASS, no type errors.

- [ ] **Step 5: Commit**

```bash
git add frontend/tests/
git commit -m "test: add React component tests (60%+ coverage)"
```

- [ ] **Step 6: Push Phase 4 to GitHub**

```bash
git push origin main
```

---

## Self-Review Notes

**Spec coverage:** Milestone 4A (upload form, policy list, loading/error states) — Tasks 1-3. Milestone 4B (findings table, filters, rule detail, risk gauge, compliance chart) — Tasks 4-5. Milestone 4C (network diagram, click-to-highlight, critical-only toggle, PNG export, risk matrix) — Task 6. Routing/auth infrastructure (Task 1) and login/register pages (Task 2) are prerequisites, following the precedent from Phases 2 and 3. All five `prompt.txt` Milestone 4A-4C commit messages are used, in order, across Tasks 3-7.

**Placeholder scan:** no "TBD"/"TODO" strings; every step has runnable code. The one intentional interim placeholder (`useAnalysis.ts`'s Task-3 stub, and `AnalysisPage`'s Task-4 `handleSelect`) is explicitly called out and replaced by name in a later task, per the "No Placeholders" exception for staged multi-task interfaces — each stands in only long enough for its own task's tests to pass, and both are fully replaced before the plan ends.

**Type consistency:** `Policy`/`Analysis`/`Finding`/`NormalizedRule` (Task 1's `types/api.ts`) are consumed identically by every later task. `usePolicies`/`useAnalysis`/`usePolicy` hook signatures match their call sites in `PoliciesPage`/`AnalysisPage`. `NetworkDiagram`/`RiskMatrix` (Task 6) consume the same `NormalizedRule`/`Finding` shapes as `FindingsTable`/`RuleDetailPanel` (Task 4).
