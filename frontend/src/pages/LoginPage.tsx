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
