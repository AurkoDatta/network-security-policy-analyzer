import { Router } from 'express';
import { authRouter } from './auth';
import { policiesRouter } from './policies';
import { analysesRouter } from './analyses';
import { complianceRulesRouter } from './complianceRules';

export const apiRouter = Router();

apiRouter.use('/auth', authRouter);
apiRouter.use('/policies', policiesRouter);
apiRouter.use('/analyses', analysesRouter);
apiRouter.use('/compliance-rules', complianceRulesRouter);
