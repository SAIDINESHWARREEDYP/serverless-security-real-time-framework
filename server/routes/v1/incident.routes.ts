import { Router, Request, Response } from 'express';
import { auditRepository } from '../../repositories/audit.repository.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';
import { requireRole } from '../../middleware/authorize.ts';

const router = Router();
const VALID_SEVERITIES = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const VALID_STATUSES = new Set(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE']);

// GET all security incidents (Authenticated)
router.get('/', authenticateMiddleware, (req: Request, res: Response) => {
  const incidents = auditRepository.getIncidents();
  return res.json({
    success: true,
    total: incidents.length,
    incidents
  });
});

// GET single incident by ID (Authenticated)
router.get('/:id', authenticateMiddleware, (req: Request, res: Response) => {
  const incident = auditRepository.getIncidentById(req.params.id);
  if (!incident) {
    return res.status(404).json({ error: `Incident ${req.params.id} not found` });
  }
  return res.json({ success: true, incident });
});

// POST create incident (SecOps Admin / Analyst)
router.post(
  '/',
  authenticateMiddleware,
  requireRole('Super Administrator', 'Security Administrator', 'Security Analyst', 'Admin'),
  (req: Request, res: Response) => {
    const { title, severity, status, root_cause, mitigation_steps, assigned_to } = req.body;
    if (!title || !severity) {
      return res.status(400).json({ error: 'Title and severity are required' });
    }
    if (!VALID_SEVERITIES.has(severity)) {
      return res.status(400).json({ error: `Invalid severity '${severity}'. Must be LOW, MEDIUM, HIGH, or CRITICAL.` });
    }
    if (status && !VALID_STATUSES.has(status)) {
      return res.status(400).json({ error: `Invalid status '${status}'.` });
    }

    const incident = auditRepository.createIncident({
      title,
      severity,
      status,
      root_cause,
      mitigation_steps,
      assigned_to: assigned_to || req.user?.username || 'secops_admin'
    });

    return res.json({
      success: true,
      message: `Incident ${incident.id} registered.`,
      incident
    });
  }
);

// PATCH update incident (Status, Notes, Assignment)
router.patch(
  '/:id',
  authenticateMiddleware,
  requireRole('Super Administrator', 'Security Administrator', 'Security Analyst', 'Admin'),
  (req: Request, res: Response) => {
    if (req.body.status && !VALID_STATUSES.has(req.body.status)) {
      return res.status(400).json({ error: `Invalid status '${req.body.status}'.` });
    }
    if (req.body.severity && !VALID_SEVERITIES.has(req.body.severity)) {
      return res.status(400).json({ error: `Invalid severity '${req.body.severity}'.` });
    }
    const updated = auditRepository.updateIncident(req.params.id, {
      status: req.body.status,
      mitigation_steps: req.body.mitigation_steps,
      root_cause: req.body.root_cause,
      assigned_to: req.body.assigned_to
    });
    if (!updated) {
      return res.status(404).json({ error: `Incident ${req.params.id} not found` });
    }
    return res.json({
      success: true,
      message: `Incident ${req.params.id} updated.`,
      incident: updated
    });
  }
);

export default router;
