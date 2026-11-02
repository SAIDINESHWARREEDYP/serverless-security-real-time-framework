import { Router } from 'express';
import { authController } from '../../controllers/auth.controller.ts';
import { loginRateLimitMiddleware } from '../../middleware/rateLimiter.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';
import { requireRole } from '../../middleware/authorize.ts';

const router = Router();

router.post('/login', loginRateLimitMiddleware, authController.login);
router.post('/mfa/verify', authController.verifyMfa);
router.post('/mfa/setup', authenticateMiddleware, authController.setupMfa);
router.post('/register', authController.register);
router.post('/revoke-session', authenticateMiddleware, authController.revokeSession);
router.post('/change-password', authenticateMiddleware, authController.changePassword);
router.get('/me', authenticateMiddleware, authController.getMe);

export default router;
