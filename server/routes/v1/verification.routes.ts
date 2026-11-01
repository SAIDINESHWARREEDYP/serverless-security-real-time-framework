import { Router } from 'express';
import { verificationController } from '../../controllers/verification.controller.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';

const router = Router();

router.post('/invoke', authenticateMiddleware, verificationController.verifyInvoke);
router.post('/evaluate', authenticateMiddleware, verificationController.verifyInvoke);
router.get('/functions', authenticateMiddleware, verificationController.getFunctions);

export default router;
