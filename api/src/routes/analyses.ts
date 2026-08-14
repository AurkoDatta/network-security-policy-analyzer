import { Router, Response } from 'express';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';
import { Analysis } from '../models/Analysis';
import { Policy } from '../models/Policy';
import { generateReportPdf } from '../services/reportService';

export const analysesRouter = Router();

analysesRouter.use(authenticate);

analysesRouter.get('/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const analysis = await Analysis.findById(req.params.id);
  if (!analysis) {
    res.status(404).json({ error: 'Analysis not found' });
    return;
  }
  const policy = await Policy.findById(analysis.policy_id);
  if (!policy || policy.user_id !== req.userId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  res.status(200).json(analysis);
});

analysesRouter.get('/:id/report', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const analysis = await Analysis.findById(req.params.id);
  if (!analysis) {
    res.status(404).json({ error: 'Analysis not found' });
    return;
  }
  const policy = await Policy.findById(analysis.policy_id);
  if (!policy || policy.user_id !== req.userId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  const pdf = await generateReportPdf(policy, analysis);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="analysis-${analysis.id}.pdf"`);
  res.status(200).send(pdf);
});
