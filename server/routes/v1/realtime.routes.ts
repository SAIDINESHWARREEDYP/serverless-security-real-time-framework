import { Router, Request, Response } from 'express';
import { auditRepository } from '../../repositories/audit.repository.ts';

const router = Router();

router.get('/stream', (req: Request, res: Response) => {
  // Set SSE Headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });

  const latestRows = auditRepository.getEvents(1, 0);
  // Send initial handshake
  const initialPayload = JSON.stringify({
    type: 'CONNECTED',
    serverTime: new Date().toISOString(),
    connectionMode: 'SERVER_SENT_EVENTS',
    activeIncidents: auditRepository.getIncidents().length,
    totalAuditRecords: auditRepository.getTotalCount(),
    latestAuditId: latestRows[0]?.id || 0
  });
  res.write(`data: ${initialPayload}\n\n`);

  let heartbeat: ReturnType<typeof setInterval>;
  let unsubscribe = () => {};

  const cleanup = () => {
    clearInterval(heartbeat);
    unsubscribe();
  };

  // Subscribe to live audit repository events
  unsubscribe = auditRepository.subscribe((event) => {
    try {
      res.write(`data: ${JSON.stringify(event)}\n\n`);
    } catch {
      cleanup();
    }
  });

  // Heartbeat every 15 seconds to keep connection alive
  heartbeat = setInterval(() => {
    try {
      res.write(`: heartbeat ${new Date().toISOString()}\n\n`);
    } catch {
      cleanup();
    }
  }, 15000);

  req.on('close', cleanup);
});

export default router;
