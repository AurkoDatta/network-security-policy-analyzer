import { Router, Request, Response } from 'express';

export const policiesRouter = Router();

policiesRouter.get('/', (req: Request, res: Response): void => {
  res.status(501).json({ message: 'not implemented' });
});
