import { Router } from 'express';
import { threatController } from '../../controllers/threat.controller.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';

const router = Router();

router.get('/alerts', authenticateMiddleware, threatController.getAlerts);
router.post('/alerts/:id/ack', authenticateMiddleware, threatController.ackAlert);
router.post('/scan', authenticateMiddleware, threatController.scanPayload);

export default router;
