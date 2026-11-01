import { Router } from 'express';
import { policyController } from '../../controllers/policy.controller.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';
import { requireRole } from '../../middleware/authorize.ts';

const router = Router();

router.get('/', authenticateMiddleware, policyController.getPolicy);
router.put('/', authenticateMiddleware, requireRole('Admin'), policyController.updatePolicy);
router.get('/rules', authenticateMiddleware, policyController.getRules);
router.post('/rules', authenticateMiddleware, requireRole('Admin'), policyController.addRule);
router.delete('/rules/:id', authenticateMiddleware, requireRole('Admin'), policyController.deleteRule);

export default router;
