import { Router, Response } from 'express';
import multer from 'multer';
import { z } from 'zod';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';
import { env } from '../config/env';
import { Policy } from '../models/Policy';
import { parsePolicyViaAnalyzer } from '../services/analyzerClient';

export const policiesRouter = Router();

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: env.maxFileSize } });

const SOURCE_TYPE_MAP: Record<string, string> = {
  aws: 'security_group',
  firewall: 'firewall',
  iam: 'iam_policy',
};

const uploadMetadataSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional().default(''),
  source_type: z.enum(['aws', 'firewall', 'iam']),
});

policiesRouter.use(authenticate);

policiesRouter.post(
  '/upload',
  (req, res, next) => {
    upload.single('file')(req, res, (err) => {
      if (err && err.code === 'LIMIT_FILE_SIZE') {
        res.status(413).json({ error: 'File exceeds maximum allowed size' });
        return;
      }
      if (err) {
        res.status(400).json({ error: 'File upload failed' });
        return;
      }
      next();
    });
  },
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const parsed = uploadMetadataSchema.safeParse(req.body);
    if (!parsed.success || !req.file) {
      res.status(400).json({ error: 'Invalid upload: name, source_type, and file are required' });
      return;
    }

    const { name, description, source_type } = parsed.data;
    const analyzerSourceType = SOURCE_TYPE_MAP[source_type];

    try {
      const normalized_rules = await parsePolicyViaAnalyzer(req.file.buffer, analyzerSourceType, req.file.originalname);
      const policy = await Policy.create({
        user_id: req.userId,
        name,
        description,
        source_type,
        raw_content: req.file.buffer.toString('utf-8'),
        normalized_rules,
        tags: [],
      });
      res.status(201).json(policy);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  },
);

policiesRouter.get('/', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const policies = await Policy.find({ user_id: req.userId }).sort({ created_at: -1 });
  res.status(200).json(policies);
});

policiesRouter.get('/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const policy = await Policy.findById(req.params.id);
  if (!policy) {
    res.status(404).json({ error: 'Policy not found' });
    return;
  }
  if (policy.user_id !== req.userId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  res.status(200).json(policy);
});

policiesRouter.delete('/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const policy = await Policy.findById(req.params.id);
  if (!policy) {
    res.status(404).json({ error: 'Policy not found' });
    return;
  }
  if (policy.user_id !== req.userId) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  await policy.deleteOne();
  res.status(204).send();
});
