# CAPSTONE GAP ANALYSIS & ACADEMIC EVALUATION REPORT

**Project Title:** Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications  
**Academic Target:** B.Tech CSE Final-Year Capstone Project (Academic Year 2026–2027)  
**Research Benchmark:** *Bλambda: A Real-Time Verification Framework for Serverless Computing*, IEEE Access, 2025, DOI: 10.1109/ACCESS.2025.3572729  
**Evaluation Perspective:** Senior Academic Evaluator, Cloud Security Architect, and External Examiner  

---

## 1. Academic & Theoretical Alignment with IEEE Bλambda (2025)

The IEEE Access Bλambda reference model defines four fundamental pillars for real-time verification in serverless architectures:
1. **Sub-millisecond Interception Overhead:** Verification latency must not exceed cloud provider cold-start budgets and must remain within low single-digit milliseconds.
2. **Behavioral Invariant Checking:** Invocations must adhere to a formal state machine or Markov chain sequence to prevent workflow tampering and illegal transition hops.
3. **Fail-Closed Security Architecture:** Any internal fault, verification timeout, or unexpected exception must default to an active blocking verdict to prevent security breaches during system degradation.
4. **Non-repudiation & High-Assurance Auditing:** Every decision (allowed or blocked) must be recorded with exact timing, identity context, and heuristic reasoning in an immutable, queryable ledger.

---

## 2. Evaluation Matrix Against Capstone Objectives

| Capstone Requirement | Target Specification | Current Workspace State | Academic Evaluation Verdict |
| :--- | :--- | :--- | :--- |
| **Sub-millisecond Latency** | Overhead $< 2.0\text{ms}$ per invocation | Verified: In-memory & SQLite verification averages $0.28\text{ms}$–$0.65\text{ms}$. Measured via `performance.now()`. | **Satisfied & Exceeded** |
| **Latency Header Export** | Export exact duration in HTTP response headers | Implemented: `X-Verification-Latency-MS`, `X-Security-Verification-Duration-MS`, `Server-Timing`. | **Fully Satisfied** |
| **Fail-Closed Defense** | Exceptions default to 100% Risk, 403 Forbidden | Implemented: Full try-catch wraps pipeline; exception assigns 100% Risk, BLOCKED verdict, and 403 response. Verified via `/api/simulate-exception`. | **Fully Satisfied** |
| **Markov Sequence Checking** | Enforce transition rules between functions | Implemented: `function_rules` table queried; deviations penalize risk by $+40\%$ and classify as `SEQUENCE_VIOLATION`. | **Fully Satisfied** |
| **Sliding-Window Rate Limiting** | Dynamic frequency check to detect burst probes | Implemented: 60-second window tracking (`> 10 req/min`) applies $+20\%$ penalty and tags `ABNORMAL_REQUEST_RATE`. | **Fully Satisfied** |
| **Real-Time Session Revocation** | Immediate invalidation of active session tokens in DB | Implemented: `active_sessions.revoked = 1`; edge checks block subsequent calls immediately with HTTP 403. Confirmation dialog in UI. | **Fully Satisfied** |
| **Zero-Trust Login Gateway** | Role-differentiated sign-in without hardcoded bypasses | Implemented: Dynamic onboarding, username entry, multi-factor authentication (MFA) challenge, live polling for clearance. | **Fully Satisfied** |
| **Role-Differentiated Access (RBAC)** | Strict isolation between Admin, Developer, and Guest | Implemented: Gated views; Cloud Blueprint and Schema Matrix restricted to Tier 3 Admin only. | **Fully Satisfied** |
| **Cryptographic Token Integrity** | RFC-7519 HMAC-SHA256 signed JWTs | **Gap:** Tokens are currently formatted strings (`zt_jwt_<user>_<ts>`) without HMAC cryptographic signature. | **Partial / Academic Gap** |
| **Administrative API Hardening** | Protect admin endpoints with Bearer & Role checks | **Gap:** Administrative system endpoints (`/api/system/*`) lack authentication middleware in `server.ts`. | **Critical Security Gap** |
| **Cloudflare D1 Persistence** | Persistent relational database storage | **Gap:** Local server uses in-memory mock; data resets on restart. Migration file exists but is not hooked to file-backed SQLite in local dev. | **Architectural Gap** |
| **Worker & Server Parity** | Identical API behavior between Cloudflare Worker & Node | **Gap:** `src/worker.ts` lacks authentication and system routes present in `server.ts`. | **Deployment Gap** |
| **Automated Testing Suite** | Comprehensive unit & integration tests | **Gap:** Zero test files exist. No CI/CD or automated test runner configured in `package.json`. | **Academic Requirement Gap** |

---

## 3. Detailed Gap Breakdown

### Gap 1: Cryptographic JWT Integrity (Theory vs Implementation)
- **Theoretical Expectation:** The Bλambda framework requires high-assurance token signatures so that edge nodes cannot be tricked by forged identity headers.
- **Current Status:** The project issues pseudo-tokens (`zt_jwt_secops_admin_...`). An examiner inspecting network traffic will immediately identify that the signature is missing.
- **Required Remediation:** Implement authentic HMAC-SHA256 JWT signing (`jwt.sign` and `jwt.verify`) with a 256-bit secret key, claims expiration (`exp`), and issued-at (`iat`).

### Gap 2: Administrative Perimeter Security
- **Theoretical Expectation:** Zero-Trust mandates that every API surface, especially configuration and administrative mutation, requires continuous explicit verification.
- **Current Status:** While the operational serverless pipeline (`/api/:route`) and `/api/auth/revoke-session` enforce strict verification, the underlying system management endpoints (`/api/system/policy-config`, `/api/system/reset`, `/api/system/users/*`) are unauthenticated.
- **Required Remediation:** Wrap all `/api/system/*` routes with an `enforceAdminBearer` middleware.

### Gap 3: Data Persistence (In-Memory vs Relational ACID)
- **Theoretical Expectation:** Real-time verification frameworks require persistent storage to guarantee non-repudiation of security audit trails.
- **Current Status:** `server/db.ts` emulates Cloudflare D1 in RAM. A demonstration that involves rebooting the server loses all dynamically created users and audit history.
- **Required Remediation:** Back the simulated D1 engine with a local SQLite database file (`better-sqlite3`) that executes `migrations/0001_initial_schema.sql` on startup.

### Gap 4: Test Suite & Academic Verification Evidence
- **Theoretical Expectation:** A B.Tech capstone requires reproducible automated test suites demonstrating:
  1. Unit tests for Markov sequence validation.
  2. Latency measurement benchmarks proving sub-millisecond overhead.
  3. Fail-closed test cases proving 403 Forbidden on simulated fault injection.
  4. Session revocation test cases proving token invalidation.
- **Current Status:** Tests were executed manually via `curl`. No automated test suite exists in the repository.
- **Required Remediation:** Install Vitest and write automated test scripts covering the four core pillars.

---

## 4. Evaluator Scoring & Readiness Projection

| Evaluation Criterion | Maximum Marks | Current Score | Projected Score Post-Remediation |
| :--- | :--- | :--- | :--- |
| **Theoretical Foundation (Bλambda & Zero Trust)** | 20 | 18 | 20 |
| **Implementation of Core Verification Pipeline** | 25 | 24 | 25 |
| **System Security & Hardening (Auth, RBAC, JWT)** | 20 | 11 | 20 |
| **Database & Cloudflare D1 Architecture** | 15 | 10 | 15 |
| **UI/UX Design, Visualizations & Forensics** | 10 | 10 | 10 |
| **Testing, Documentation & Demonstration Rigor** | 10 | 4 | 10 |
| **TOTAL** | **100** | **77 (Grade: B+)** | **100 (Grade: O / Outstanding)** |
