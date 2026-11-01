import { Router, Request, Response } from 'express';
import { auditRepository } from '../../repositories/audit.repository.ts';
import { authenticateMiddleware } from '../../middleware/authenticate.ts';

const router = Router();

// GET all security incidents
router.get('/', (req: Request, res: Response) => {
  const incidents = auditRepository.getIncidents();
  return res.json({
    success: true,
    total: incidents.length,
    incidents
  });
});

// GET single incident by ID
router.get('/:id', (req: Request, res: Response) => {
  const incident = auditRepository.getIncidentById(req.params.id);
  if (!incident) {
    return res.status(404).json({ error: `Incident ${req.params.id} not found` });
  }
  return res.json({ success: true, incident });
});

// POST create incident (SecOps Admin / Analyst)
router.post('/', authenticateMiddleware, (req: Request, res: Response) => {
  const { title, severity, status, root_cause, mitigation_steps, assigned_to } = req.body;
  if (!title || !severity) {
    return res.status(400).json({ error: 'Title and severity are required' });
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
});

// PATCH update incident (Status, Notes, Assignment)
router.patch('/:id', authenticateMiddleware, (req: Request, res: Response) => {
  const updated = auditRepository.updateIncident(req.params.id, req.body);
  if (!updated) {
    return res.status(404).json({ error: `Incident ${req.params.id} not found` });
  }
  return res.json({
    success: true,
    message: `Incident ${req.params.id} updated.`,
    incident: updated
  });
});

export default router;
