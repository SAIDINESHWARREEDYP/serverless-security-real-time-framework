# PHASE 12 — Performance & Overhead Evaluation

## 1. Reproducible Benchmarking Methodology

All measurements are produced directly by the reproducible benchmark script `scripts/benchmark.ts` (`npm run benchmark`), which isolates execution in an ephemeral SQLite WAL file via `SECURITY_DB_PATH` so production database records remain untouched:

1. **Isolated 15-Step Pipeline Micro-Benchmark ($W = 25$ warmup, $N = 200$ invocations):** Direct timing of `verificationService.execute15StepPipeline()` via `performance.now()`.
2. **Live Express HTTP Gateway Benchmark ($W = 5$ warmup, $N = 50$ sequential `POST /api/v1/verify/invoke` requests):** Measured against an in-process Express server (`127.0.0.1`), recording both server-side `X-Verification-Latency-MS` header processing and full client-to-server HTTP round-trip latency including JSON parsing, JWT signature verification, SQLite session lookup, RBAC check, threat scan, and SHA-256 hash-chained audit write (`280` audit records sealed per run).

---

## 2. Empirical Latency Measurements (Two Consecutive Reproducible Runs)

| Benchmark Mode | Sample Count ($N$) | Run 1 Mean | Run 1 p50 | Run 1 p95 | Run 2 Mean | Run 2 p50 | Run 2 p95 | Throughput |
|---|---|---|---|---|---|---|---|---|
| **Isolated 15-Step Pipeline** (`execute15StepPipeline`) | 200 | **1.140 ms** | **1.111 ms** | **1.442 ms** | **1.300 ms** | **1.017 ms** | **3.244 ms** | **766–873 req/s** |
| **Live HTTP Gateway** (`X-Verification-Latency-MS` header) | 50 | **1.577 ms** | **1.247 ms** | **1.755 ms** | **1.622 ms** | **1.297 ms** | **3.467 ms** | **126–135 req/s** |
| **Live HTTP End-to-End Round-Trip** (`Client -> Express -> Client`) | 50 | **7.088 ms** | **6.197 ms** | **13.951 ms** | **7.589 ms** | **6.494 ms** | **12.915 ms** | **126–135 req/s** |

---

## 3. Architectural Latency Comparison

| Verification Architecture | Execution Model | Measured / Published Metric | Fail-Closed Behavior |
|---|---|---|---|
| **BAMBDA** (Shin et al., *IEEE Access* 2025) [1] | Asynchronous / log-group temporal assertion with Lambda instrumentation | **8.12% relative warm-start execution overhead** (published) | Post-invocation / runtime monitor |
| **Proposed Framework — Isolated Pipeline** (`npm run benchmark`) | Synchronous in-line 15-step gateway verification (Node.js + `node:sqlite`) | **1.140–1.300 ms mean** (p50 `1.017–1.111 ms`) | **Guaranteed Fail-Closed (`DENY` on fault)** |
| **Proposed Framework — Full HTTP Gateway** (`npm run benchmark`) | Full Express middleware + JWT + SQLite WAL audit hash chain | **1.577–1.622 ms header** (`7.088–7.589 ms` HTTP RTT) | **Guaranteed Fail-Closed (`401`/`403`/`503`)** |

> **Scope Note:** Edge worker latency on production Cloudflare Workers + distributed D1 across global POPs is not claimed numerically because `wrangler` CLI credentials and remote Cloudflare account tokens are absent in this offline evaluation sandbox; all edge Worker tests ran against local `node:sqlite` D1 emulation.
