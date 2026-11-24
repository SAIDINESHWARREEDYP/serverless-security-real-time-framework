import { Router } from 'express';
import { auditController } from '../../controllers/audit.controller.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';
import { requirePermission, requireRole } from '../../middleware/authorize.ts';

const router = Router();

router.get('/events', authenticateMiddleware, requirePermission('audit:read'), auditController.getEvents);
router.get('/logs', authenticateMiddleware, requirePermission('audit:read'), auditController.getEvents);
router.get('/verify-chain', authenticateMiddleware, requirePermission('audit:read'), auditController.verifyChain);
router.get('/anchor-status', authenticateMiddleware, requirePermission('audit:read'), auditController.getAnchorStatus);
router.post(
  '/baseline-legacy',
  authenticateMiddleware,
  requireRole('Super Administrator', 'Security Administrator', 'Admin'),
  auditController.baselineLegacy
);
router.post(
  '/rotate-anchor-key',
  authenticateMiddleware,
  requireRole('Super Administrator', 'Security Administrator', 'Admin'),
  auditController.rotateAnchorKey
);
router.post(
  '/clear',
  authenticateMiddleware,
  requireRole('Super Administrator', 'Security Administrator', 'Admin'),
  auditController.clearEvents
);

export default router;
