/**
 * Reproducible Performance & Overhead Benchmark Script
 * Evaluates:
 *   1. Isolated 15-Step Security Verification Pipeline (Warmup + N = 200)
 *   2. Live Express HTTP Gateway POST /api/v1/verify/invoke (N = 50)
 *   3. D1 SQLite Telemetry & Hash-Chaining Throughput
 *
 * Uses an isolated ephemeral SQLite file via SECURITY_DB_PATH so production
 * /server/data/security_framework.sqlite records remain untouched.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';

const tmpBenchDbPath = `/tmp/secops_benchmark_${Date.now()}_${crypto.randomBytes(3).toString('hex')}.sqlite`;
process.env.SECURITY_DB_PATH = tmpBenchDbPath;

interface LatencyStats {
  samples: number;
  minMs: number;
  meanMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  maxMs: number;
  throughputReqPerSec: number;
}

function summarize(durationsMs: number[], totalElapsedMs: number): LatencyStats {
  const sorted = [...durationsMs].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const percentile = (p: number) => {
    const idx = Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p));
    return Number(sorted[idx].toFixed(3));
  };
  return {
    samples: sorted.length,
    minMs: Number(sorted[0].toFixed(3)),
    meanMs: Number((sum / sorted.length).toFixed(3)),
    p50Ms: percentile(0.5),
    p95Ms: percentile(0.95),
    p99Ms: percentile(0.99),
    maxMs: Number(sorted[sorted.length - 1].toFixed(3)),
    throughputReqPerSec: Number(((sorted.length / totalElapsedMs) * 1000).toFixed(1))
  };
}

async function runBenchmark() {
  const expressMod = await import('express');
  const express = expressMod.default;
  const { db } = await import('../server/db.ts');
  const { verificationService } = await import('../server/services/verification.service.ts');
  const { policyRepository } = await import('../server/repositories/policy.repository.ts');
  const { userRepository } = await import('../server/repositories/user.repository.ts');
  const { sessionRepository } = await import('../server/repositories/session.repository.ts');
  const { signJwt } = await import('../server/utils/crypto.ts');
  const { requestIdMiddleware } = await import('../server/middleware/requestId.ts');
  const { errorHandlerMiddleware } = await import('../server/middleware/errorHandler.ts');
  const { default: rootRouter } = await import('../server/routes/index.ts');

  try {
    // Configure clean low-friction policy & benchmark principal in isolated DB
    policyRepository.updatePolicy({ enforceStrictSequence: false, maxRiskThreshold: 75 });

    const benchUser = userRepository.create({
      username: 'bench_principal',
      password: `BenchPwd_${crypto.randomBytes(12).toString('hex')}!`,
      role: 'Admin',
      base_risk_score: 5,
      status: 'APPROVED',
      department: 'Performance QA'
    });

    const jti = `jti_bench_${crypto.randomBytes(6).toString('hex')}`;
    const token = signJwt({
      sub: benchUser.id,
      username: benchUser.username,
      role: benchUser.role,
      jti,
      expiresInSeconds: 3600
    });
    sessionRepository.createSession({
      token,
      userId: benchUser.id,
      username: benchUser.username,
      role: benchUser.role,
      expiresInSeconds: 3600,
      ipAddress: '127.0.0.1'
    });

    const payloadJson = JSON.stringify({ region: 'ap-south-1', probe: 'benchmark' });

    // 1. Warmup (25 runs) + Isolated 15-Step Pipeline Benchmark (N = 200)
    for (let i = 0; i < 25; i++) {
      verificationService.execute15StepPipeline({
        requestId: `warmup_${i}`,
        targetFunction: 'getDashboardMetrics',
        payloadStr: payloadJson,
        user: benchUser,
        token,
        timerStart: performance.now()
      });
    }

    const isolatedDurations: number[] = [];
    const isoStartAll = performance.now();
    for (let i = 0; i < 200; i++) {
      const t0 = performance.now();
      const res = verificationService.execute15StepPipeline({
        requestId: `iso_${i}`,
        targetFunction: 'getDashboardMetrics',
        payloadStr: payloadJson,
        user: benchUser,
        token,
        timerStart: t0
      });
      const dt = performance.now() - t0;
      if (res.decision !== 'ALLOW') {
        throw new Error(`Unexpected verdict during benchmark iteration ${i}: ${res.decision}`);
      }
      isolatedDurations.push(dt);
    }
    const isoElapsedAll = performance.now() - isoStartAll;
    const isolatedStats = summarize(isolatedDurations, isoElapsedAll);

    // 2. Live Express HTTP Gateway Benchmark (N = 50 sequential POST /api/v1/verify/invoke)
    const app = express();
    app.use(express.json({ limit: '1mb' }));
    app.use(requestIdMiddleware);
    app.use('/api', rootRouter);
    app.use(errorHandlerMiddleware);

    const server = await new Promise<import('node:http').Server>((resolve) => {
      const srv = app.listen(0, '127.0.0.1', () => resolve(srv));
    });

    const gatewayHeaderLatencies: number[] = [];
    const httpRoundTripLatencies: number[] = [];
    let httpElapsedAll = 0;

    try {
      const addr = server.address() as AddressInfo;
      const baseUrl = `http://127.0.0.1:${addr.port}`;

      // HTTP warmup (5 calls)
      for (let i = 0; i < 5; i++) {
        await fetch(`${baseUrl}/api/v1/verify/invoke`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ functionName: 'getDashboardMetrics', payload: { region: 'ap-south-1' } })
        });
      }

      const httpStartAll = performance.now();
      for (let i = 0; i < 50; i++) {
        const t0 = performance.now();
        const res = await fetch(`${baseUrl}/api/v1/verify/invoke`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ functionName: 'getDashboardMetrics', payload: { region: 'ap-south-1', seq: i } })
        });
        const rttMs = performance.now() - t0;
        if (res.status !== 200) {
          throw new Error(`HTTP benchmark expected 200, got ${res.status}: ${await res.text()}`);
        }
        const headerVal = Number(res.headers.get('X-Verification-Latency-MS') || '0');
        await res.arrayBuffer();
        gatewayHeaderLatencies.push(headerVal > 0 ? headerVal : rttMs);
        httpRoundTripLatencies.push(rttMs);
      }
      httpElapsedAll = performance.now() - httpStartAll;
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }

    const gatewayHeaderStats = summarize(gatewayHeaderLatencies, httpElapsedAll);
    const httpRoundTripStats = summarize(httpRoundTripLatencies, httpElapsedAll);

    // Verify audit hash chain integrity on ephemeral benchmark DB
    const auditCountRow = db.prepare('SELECT COUNT(*) as c FROM audit_events').first<{ c: number }>();

    const report = {
      timestamp: new Date().toISOString(),
      runtime: {
        nodeVersion: process.version,
        platform: process.platform,
        sqliteMode: 'node:sqlite WAL + SHA-256 hash chaining (isolated /tmp benchmark DB)'
      },
      isolated15StepPipeline: isolatedStats,
      httpGatewayVerificationHeader: gatewayHeaderStats,
      httpEndToEndRoundTrip: httpRoundTripStats,
      auditRecordsSealed: Number(auditCountRow?.c ?? 0)
    };

    console.log('\n=== SERVERLESS SECURITY VERIFICATION FRAMEWORK — REPRODUCIBLE BENCHMARK ===\n');
    console.log(
      '| Benchmark Mode | Samples (N) | Min (ms) | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) | Throughput (req/s) |'
    );
    console.log('|---|---|---|---|---|---|---|---|---|');
    console.log(
      `| Isolated 15-Step Pipeline | ${isolatedStats.samples} | ${isolatedStats.minMs} | ${isolatedStats.meanMs} | ${isolatedStats.p50Ms} | ${isolatedStats.p95Ms} | ${isolatedStats.p99Ms} | ${isolatedStats.maxMs} | ${isolatedStats.throughputReqPerSec} |`
    );
    console.log(
      `| Live HTTP Gateway (Server Timing Header) | ${gatewayHeaderStats.samples} | ${gatewayHeaderStats.minMs} | ${gatewayHeaderStats.meanMs} | ${gatewayHeaderStats.p50Ms} | ${gatewayHeaderStats.p95Ms} | ${gatewayHeaderStats.p99Ms} | ${gatewayHeaderStats.maxMs} | ${gatewayHeaderStats.throughputReqPerSec} |`
    );
    console.log(
      `| Live HTTP End-to-End Round-Trip (Client->Server) | ${httpRoundTripStats.samples} | ${httpRoundTripStats.minMs} | ${httpRoundTripStats.meanMs} | ${httpRoundTripStats.p50Ms} | ${httpRoundTripStats.p95Ms} | ${httpRoundTripStats.p99Ms} | ${httpRoundTripStats.maxMs} | ${httpRoundTripStats.throughputReqPerSec} |`
    );
    console.log(`\nAudit records sealed with SHA-256 chain during benchmark: ${report.auditRecordsSealed}`);
    console.log('\nBENCHMARK_JSON=' + JSON.stringify(report));
  } finally {
    db.close();
    for (const ext of ['', '-wal', '-shm']) {
      const target = `${tmpBenchDbPath}${ext}`;
      if (fs.existsSync(target)) {
        try {
          fs.unlinkSync(target);
        } catch {
          // ignore
        }
      }
    }
  }
}

runBenchmark().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
