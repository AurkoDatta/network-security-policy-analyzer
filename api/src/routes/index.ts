import { Router } from 'express';
import { policiesRouter } from './policies';
import { analysesRouter } from './analyses';
import { complianceRulesRouter } from './complianceRules';

export const apiRouter = Router();

apiRouter.use('/policies', policiesRouter);
apiRouter.use('/analyses', analysesRouter);
apiRouter.use('/compliance-rules', complianceRulesRouter);
