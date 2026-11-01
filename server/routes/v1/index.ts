import { Router } from 'express';
import authRoutes from './auth.routes.ts';
import userRoutes from './user.routes.ts';
import rbacRoutes from './rbac.routes.ts';
import verificationRoutes from './verification.routes.ts';
import threatRoutes from './threat.routes.ts';
import policyRoutes from './policy.routes.ts';
import auditRoutes from './audit.routes.ts';
import analyticsRoutes from './analytics.routes.ts';
import healthRoutes from './health.routes.ts';
import incidentRoutes from './incident.routes.ts';
import realtimeRoutes from './realtime.routes.ts';

const v1Router = Router();

v1Router.use('/auth', authRoutes);
v1Router.use('/users', userRoutes);
v1Router.use('/rbac', rbacRoutes);
v1Router.use('/verify', verificationRoutes);
v1Router.use('/security', threatRoutes);
v1Router.use('/policies', policyRoutes);
v1Router.use('/audit', auditRoutes);
v1Router.use('/analytics', analyticsRoutes);
v1Router.use('/system', healthRoutes);
v1Router.use('/incidents', incidentRoutes);
v1Router.use('/realtime', realtimeRoutes);

export default v1Router;
