import { Router, Request, Response } from 'express';

export const analysesRouter = Router();

analysesRouter.get('/', (req: Request, res: Response): void => {
  res.status(501).json({ message: 'not implemented' });
});
