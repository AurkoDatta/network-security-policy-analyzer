import { hashPassword, issueToken, verifyPassword } from '../../src/services/authService';
import jwt from 'jsonwebtoken';
import { env } from '../../src/config/env';

describe('authService', () => {
  it('hashes a password and verifies it correctly', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).not.toEqual('correct horse battery staple');
    expect(await verifyPassword('correct horse battery staple', hash)).toBe(true);
    expect(await verifyPassword('wrong password', hash)).toBe(false);
  });

  it('issues a JWT containing the userId', () => {
    const token = issueToken('user-123');
    const payload = jwt.verify(token, env.jwtSecret) as { userId: string };
    expect(payload.userId).toBe('user-123');
  });
});
