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

  // Send initial handshake
  const initialPayload = JSON.stringify({
    type: 'CONNECTED',
    serverTime: new Date().toISOString(),
    connectionMode: 'SERVER_SENT_EVENTS',
    activeIncidents: auditRepository.getIncidents().length,
    totalAuditRecords: auditRepository.getTotalCount()
  });
  res.write(`data: ${initialPayload}\n\n`);

  // Subscribe to live audit repository events
  const unsubscribe = auditRepository.subscribe((event) => {
    try {
      res.write(`data: ${JSON.stringify(event)}\n\n`);
    } catch {
      // client connection closed
    }
  });

  // Heartbeat every 15 seconds to keep connection alive
  const heartbeat = setInterval(() => {
    try {
      res.write(`: heartbeat ${new Date().toISOString()}\n\n`);
    } catch {
      clearInterval(heartbeat);
    }
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
});

export default router;
