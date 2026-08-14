import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';

const SALT_ROUNDS = 10;
const TOKEN_TTL = '24h';

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function issueToken(userId: string): string {
  return jwt.sign({ userId }, env.jwtSecret, { expiresIn: TOKEN_TTL });
}
