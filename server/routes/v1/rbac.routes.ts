import { Router } from 'express';
import { rbacController } from '../../controllers/rbac.controller.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';
import { requirePermission } from '../../middleware/authorize.ts';

const router = Router();

router.get('/roles', authenticateMiddleware, rbacController.getRoles);
router.get('/permissions', authenticateMiddleware, rbacController.getPermissions);
router.get('/matrix', authenticateMiddleware, requirePermission('permissions:read'), rbacController.getMatrix);
router.post('/assign', authenticateMiddleware, requirePermission('roles:assign'), rbacController.assignRole);
router.get('/history', authenticateMiddleware, requirePermission('permissions:read'), rbacController.getChangeHistory);
router.get('/access-denied', authenticateMiddleware, requirePermission('audit:read'), rbacController.getAccessDeniedHistory);

export default router;
