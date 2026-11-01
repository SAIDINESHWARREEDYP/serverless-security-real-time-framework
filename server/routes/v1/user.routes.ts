import { Router } from 'express';
import { userController } from '../../controllers/user.controller.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';
import { requireRole } from '../../middleware/authorize.ts';

const router = Router();

router.get('/', authenticateMiddleware, requireRole('Admin'), userController.getUsers);
router.get('/:id', authenticateMiddleware, userController.getUserById);
router.post('/:id/approve', authenticateMiddleware, requireRole('Admin'), userController.approveUser);
router.post('/:id/reject', authenticateMiddleware, requireRole('Admin'), userController.rejectUser);
router.patch('/:id/status', authenticateMiddleware, requireRole('Admin'), userController.updateStatus);
router.delete('/:id', authenticateMiddleware, requireRole('Admin'), userController.deleteUser);

export default router;
