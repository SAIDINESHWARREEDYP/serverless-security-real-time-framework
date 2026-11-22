# PHASE 12 — Performance & Overhead Evaluation

## 1. Benchmarking Methodology

To quantify the operational overhead introduced by the **15-Step Serverless Security Verification Pipeline**, two reproducible benchmarks were measured directly against the running Node.js + SQLite implementation (`node:sqlite`, TypeScript via `tsx`):

1. **Isolated 15-Step Pipeline Micro-Benchmark ($N = 200$ invocations):** Direct timing of `verificationService.execute15StepPipeline()` via `performance.now()`.
2. **End-to-End Live HTTP Gateway Benchmark ($N = 20$ sequential `POST /api/v1/verify/invoke` requests):** Measured against `http://localhost:3000` using the response `X-Verification-Latency-MS` header, including JSON parsing, JWT signature validation, SQLite session check, RBAC check, sequence validation, threat scan, and SHA-256 chained audit persistence.

---

## 2. Empirical Latency Measurements

| Benchmark Mode | Sample Count ($N$) | Mean Latency | Median (p50) | p95 Latency | p99 / Max Measured |
|---|---|---|---|---|---|
| **Isolated 15-Step Pipeline** (`execute15StepPipeline`) | 200 | **0.586 ms** | **0.499 ms** | **0.822 ms** | **3.421 ms** (p99) |
| **Live Express HTTP Endpoint** (`POST /api/v1/verify/invoke`) | 20 | **1.741 ms** | **1.535 ms** | **4.346 ms** | **4.346 ms** (p95/max in sample) |

---

## 3. Architectural Latency Comparison

| Verification Architecture | Execution Model | Measured / Published Metric | Fail-Closed Behavior |
|---|---|---|---|
| **BAMBDA** (Shin et al., *IEEE Access* 2025) [1] | Asynchronous / log-group temporal assertion with Lambda instrumentation | **8.12% relative warm-start execution overhead** (published) | Post-invocation / runtime monitor |
| **Proposed Framework — Isolated Pipeline** | Synchronous in-line 15-step gateway verification (Node.js + SQLite) | **0.586 ms mean** (p50 0.499 ms, p95 0.822 ms) | **Guaranteed Fail-Closed (`DENY` on fault)** |
| **Proposed Framework — Full HTTP API** | Full Express middleware + JWT + SQLite audit write | **1.741 ms mean** (p50 1.535 ms, p95 4.346 ms) | **Guaranteed Fail-Closed (`401`/`403`/`503`)** |

> **Scope Note:** Edge worker latency on production Cloudflare Workers + distributed D1 across global POPs is not claimed numerically here because remote Cloudflare deployment was not executed in this offline evaluation environment.
