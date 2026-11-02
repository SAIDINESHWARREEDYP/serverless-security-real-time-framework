import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { requestIdMiddleware } from './server/middleware/requestId.ts';
import { apiBurstRateLimitMiddleware } from './server/middleware/rateLimiter.ts';
import { errorHandlerMiddleware } from './server/middleware/errorHandler.ts';
import rootRouter from './server/routes/index.ts';
import { CONFIG } from './server/config/env.ts';
import { logger } from './server/utils/logger.ts';

const app = express();
const PORT = CONFIG.PORT;

// Standard payload parsing with size boundary
app.use(express.json({ limit: CONFIG.MAX_PAYLOAD_BYTES }));
app.use(express.urlencoded({ extended: true, limit: CONFIG.MAX_PAYLOAD_BYTES }));

// Strict CORS & Origin Defense
app.use((req, res, next) => {
  const origin = req.headers.origin as string;
  const host = req.headers.host;
  const isTrusted = origin && (
    CONFIG.TRUSTED_ORIGINS.some(to => to.toLowerCase() === origin.toLowerCase()) ||
    (host && origin.includes(host)) ||
    origin.endsWith('.run.app') ||
    origin.endsWith('.google.com') ||
    origin.endsWith('.googleusercontent.com') ||
    origin.endsWith('.aistudio.google.com') ||
    origin.includes('localhost') ||
    origin.includes('127.0.0.1')
  );

  if (isTrusted) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');
  } else if (!origin) {
    // Local / CLI non-browser direct calls or same-origin requests
    res.header('Vary', 'Origin');
  }

  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID, X-Simulate-Fault');
  res.header('Access-Control-Expose-Headers', 'X-Verification-Latency-MS, X-Security-Verification-Duration-MS, Server-Timing, X-Verification-Decision, X-Verification-Risk-Score, X-Request-ID, X-Verification-Trace-ID');
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'SAMEORIGIN');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Request Tracing & Correlation ID Injection
app.use(requestIdMiddleware);

// API Burst Rate Limiting
app.use('/api', apiBurstRateLimitMiddleware);

// Mount Master API Routing (/api and /api/v1)
app.use('/api', rootRouter);

// Centralized Fail-Closed Error Handling Middleware
app.use(errorHandlerMiddleware);

// Vite middleware & Static Serving
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    logger.info('SERVER_STARTUP', `Serverless Security Verification Framework running on port ${PORT}`);
  });
}

startServer();
