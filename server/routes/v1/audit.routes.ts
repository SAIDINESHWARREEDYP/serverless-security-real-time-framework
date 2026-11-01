import { Router } from 'express';
import { auditController } from '../../controllers/audit.controller.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';
import { requirePermission, requireRole } from '../../middleware/authorize.ts';

const router = Router();

router.get('/events', authenticateMiddleware, requirePermission('audit:read'), auditController.getEvents);
router.post('/clear', authenticateMiddleware, requireRole('Admin'), auditController.clearEvents);

export default router;
