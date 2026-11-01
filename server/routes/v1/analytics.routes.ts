import { Router } from 'express';
import { analyticsController } from '../../controllers/analytics.controller.ts';

const router = Router();

router.get('/overview', analyticsController.getOverview);

export default router;
