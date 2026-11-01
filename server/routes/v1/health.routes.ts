import { Router } from 'express';
import { healthController } from '../../controllers/health.controller.ts';

const router = Router();

router.get('/health', healthController.getHealth);
router.get('/d1-latency', healthController.getD1Latency);

export default router;
