import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { User } from '../models/User';
import { hashPassword, issueToken, verifyPassword } from '../services/authService';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';

export const authRouter = Router();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

authRouter.post('/register', async (req: Request, res: Response): Promise<void> => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid registration data', details: parsed.error.flatten() });
    return;
  }

  const { email, password, name } = parsed.data;
  const existing = await User.findOne({ email });
  if (existing) {
    res.status(409).json({ error: 'Email already registered' });
    return;
  }

  const password_hash = await hashPassword(password);
  const user = await User.create({ email, password_hash, name });
  res.status(201).json({ token: issueToken(user.id) });
});

authRouter.post('/login', async (req: Request, res: Response): Promise<void> => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid login data' });
    return;
  }

  const { email, password } = parsed.data;
  const user = await User.findOne({ email }).select('+password_hash');
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    res.status(401).json({ error: 'Invalid email or password' });
    return;
  }

  res.status(200).json({ token: issueToken(user.id) });
});

authRouter.post('/refresh', authenticate, (req: AuthenticatedRequest, res: Response): void => {
  res.status(200).json({ token: issueToken(req.userId as string) });
});
