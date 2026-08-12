import { Router, Request, Response } from 'express';

export const healthRouter = Router();

healthRouter.get('/', (req: Request, res: Response): void => {
  res.status(200).json({ status: 'ok', service: 'api' });
});
