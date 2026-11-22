# Comprehensive Viva Preparation Guide: Technical Questions & Defensible Answers

**Project Title:** Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications  
**Academic Degree:** Bachelor of Technology in Computer Science & Engineering (Final-Year Capstone)  
**Theoretical Reference:** IEEE Access 2025 Paper: *Bλambda: A Real-Time Verification Framework for Serverless Computing* (DOI: 10.1109/ACCESS.2025.3572729)

---

## Guide Structure
This viva preparation guide contains **42 rigorous, highly defensible questions and answers** across 8 core domains designed to prepare candidates for defense against external academic examiners, cloud security auditors, and system architects.

---

## Domain 1: Serverless Security Concepts & Problem Context

### Q1: What makes security verification in serverless architectures fundamentally different from traditional container or VM security?
**Answer:** In traditional monolithic or containerized architectures, security relies on perimeter firewalls (VPCs, subnets, security groups) and long-running host agents (EDRs) that monitor operating system syscalls. In serverless computing (FaaS):
1. **Vanishing Perimeters**: Functions execute across multi-tenant edge nodes directly accessible via HTTP gateways, object storage events, or pub/sub messages.
2. **Ephemeral Lifecycles**: Instances spin up and terminate in milliseconds, making static host-level monitoring impossible.
3. **Disaggregated Attack Surface**: Instead of one large perimeter, every single micro-function represents an independent entry point requiring per-invocation zero-trust verification.

### Q2: What is the IEEE Access 2025 *BAMBDA* paper, and how does your project build upon it?
**Answer:** The *BAMBDA* paper (*Changhee Shin, Bom Kim, and Seungsoo Lee, "BAMBDA: A Real-Time Verification Framework for Serverless Computing," IEEE Access, vol. 13, pp. 90896–90911, 2025, DOI: 10.1109/ACCESS.2025.3572729*) proposed automated code injection and centralized log-group analysis to verify temporal safety and liveness properties in AWS Lambda workflows, reporting an 8.12% runtime overhead under warm-start conditions.
Our project investigates an alternative in-line gateway architecture designed for edge runtimes (Cloudflare Workers with Cloudflare D1) and Node.js microservices. Our independently developed contributions include:
- An in-line 15-step verification pipeline intercepting requests prior to function handler invocation, with measured empirical Node.js Express benchmarks of **0.586 ms** mean isolated pipeline latency (median 0.499 ms, p95 0.822 ms) and **1.741 ms** mean end-to-end HTTP verification latency (median 1.535 ms, p95 4.346 ms).
- Native Zero-Trust identity management: PBKDF2-SHA512 hashing (100,000 rounds), laptop-accessible single-use SHA-256 recovery-code enrollment and verification, optional RFC 6238 TOTP MFA with replay prevention, and strict HS256 JWT validation.
- Stateful real-time session revocation backed by relational SQL persistence.
- Deterministic rule-based workflow transition checking (`function_rules`) to prevent unauthorized lateral jumps.
- Heuristic threat scanning across six serverless attack vectors (including AWS/GCP IMDS SSRF `169.254.169.254`).
- A tamper-evident SHA-256 hash-chained audit ledger with real-time SSE streaming.

### Q3: Why is Function Event Injection (SAS-01) ranked as the top vulnerability in the OWASP Serverless Top 10?
**Answer:** In serverless architectures, functions consume input not only from traditional HTTP bodies but also from heterogeneous event sources (Cloudflare D1 triggers, KV updates, S3 bucket events, CloudWatch events). Traditional Web Application Firewalls (WAFs) only inspect HTTP ingress, leaving internal event-driven data flows uninspected. If malicious code or SQL injection is embedded within an internal event, downstream functions execute it unsanitized. Our framework mitigates this by placing Step 7 (Payload Sanitization) in-line for every function invocation regardless of trigger source.

### Q4: Why is a "Fail-Closed" design critical in cloud security, and how is it implemented in your framework?
**Answer:** A fail-closed design guarantees that if any verification component experiences an unexpected exception, timeout, or database partition, the access decision defaults to `DENY` rather than `ALLOW`. In our framework, the `verifyInvocation()` pipeline wraps all 15 stages in a global error handler: if any unhandled error occurs, the pipeline catches it, logs a critical error event, and immediately returns HTTP 500 / 403 with `allowed: false`.

### Q5: What is the principle of least privilege (PoLP) in serverless, and how do you enforce it?
**Answer:** In serverless, functions are frequently over-privileged with wildcard IAM permissions (`*`) to simplify deployment. We enforce PoLP through Step 6 (RBAC evaluation) and Step 11 (Least-Privilege Scope Verification). Each function registers an explicit manifest of permitted actions. If an invocation requests permissions outside that scope, the framework blocks the request even if the invoking user has elevated privileges.

---

## Domain 2: Authentication & Cryptographic Security

### Q6: Why did you choose PBKDF2-SHA512 over bcrypt or raw SHA-256 for password hashing?
**Answer:** 
- Raw SHA-256 is designed for fast hashing (gigahashes/second on modern GPUs) and is completely unsuitable for passwords because it is susceptible to brute-force dictionary attacks.
- While `bcrypt` is strong, its C-based native dependencies introduce severe portability issues inside pure V8 JavaScript edge runtimes like Cloudflare Workers.
- **PBKDF2-SHA512** with 100,000 iterations is natively supported across the Web Crypto API (`crypto.subtle`) available in standard browsers, Node.js, and Cloudflare Workers, providing cryptographic resilience with zero native binary compilation overhead.

### Q7: Explain how the RFC 6238 Time-Based One-Time Password (TOTP) algorithm works mathematically.
**Answer:** TOTP calculates a 6-digit one-time passcode based on a shared secret $K$ and the current Unix epoch time $T$:
1. Compute the time counter: $C = \lfloor (T - T_0) / T_X \rfloor$, where $T_0 = 0$ and $T_X = 30\text{ seconds}$.
2. Generate the HMAC-SHA1 hash: $H = \text{HMAC-SHA1}(K, C)$.
3. Perform dynamic truncation to extract a 31-bit integer from the 20-byte hash.
4. Calculate modulo $10^6$: $\text{Code} = (\text{TruncatedHash} \bmod 1,000,000)$.
Our implementation verifies $C$, $C-1$, and $C+1$ to allow $\pm 30$ seconds of clock drift.

### Q8: What prevents timing attacks during password and token verification in your code?
**Answer:** Standard string comparison operators (`===`) terminate comparison as soon as the first mismatched byte is encountered, leaking execution time proportional to the number of matching leading characters. Our system uses constant-time comparison via `crypto.timingSafeEqual()`, ensuring that comparison time remains invariant regardless of payload equality.

### Q9: How do you handle JWT revocation if JWTs are supposed to be stateless?
**Answer:** Purely stateless JWTs cannot be revoked prior to their expiration without maintaining state. We implement a hybrid model:
1. The JWT contains an HMAC-SHA256 signature and standard claims (`sub`, `role`, `exp`), plus a unique `sessionId` claim.
2. Fast cryptographic validation (Step 4) verifies the signature in $\sim 210\mu\text{s}$.
3. Step 5 performs a fast session status check against the database/cache (`sessions` table). If an administrator revokes the session or the user logs out, the `sessionId` is invalidated, causing immediate rejection of the token without waiting for `exp` to elapse.

### Q10: How does laptop-only MFA work without requiring a mobile authenticator app?
**Answer:** Users without an authenticator app enroll using eight 8-character single-use recovery codes (`XXXX-XXXX`), which can be copied or downloaded as a `.txt` file on their laptop and confirmed immediately during first sign-in. Codes are stored solely as SHA-256 hashes, verified in constant time (`timingSafeEqual`), and consumed atomically inside SQLite `BEGIN IMMEDIATE` transactions (or D1 compare-and-set updates in the Worker) so concurrent requests cannot reuse a code. Optional RFC 6238 TOTP remains available alongside it.

---

## Domain 3: Authorization & Role-Based Access Control (RBAC)

### Q11: What are the 6 canonical roles in your framework, and what is the hierarchy?
**Answer:** The hierarchy from most to least privileged is:
1. `SUPER_ADMIN`: Complete system governance, key rotation, user approvals, policy overrides.
2. `SECURITY_ADMIN`: Threat rule management, policy tuning, incident management, session revocation.
3. `SECURITY_ANALYST`: Incident investigation, forensic log review, threat telemetry analysis.
4. `DEVELOPER`: Function authoring, workbench testing, mock invocation debugging.
5. `AUDITOR`: Read-only cryptographic audit verification and compliance export.
6. `VIEWER`: Read-only operational dashboards and high-level metric views.

### Q12: Why should an application never rely solely on role strings present in a client-supplied JWT?
**Answer:** If an authorization check relies solely on the `role` claim in a cached client JWT:
1. Privilege revocations or role demotions made by an administrator would not take effect until the token expires.
2. If token signing keys were ever misconfigured, an attacker could tamper with the role claim.
Our framework validates that the `sessionId` is active and verifies effective permissions against the server-authoritative role-permission matrix on every privileged API invocation.

### Q13: What happens when an administrator revokes a user's permissions or deactivates an account?
**Answer:** The user's status is updated to `SUSPENDED` or their role is downgraded in the D1 database. Additionally, all active sessions for that user ID in the `sessions` table are flagged as revoked. The very next invocation or API call made by that user fails at Step 5 (`ACCOUNT_STATE_CHECK`), immediately returning HTTP 403 Forbidden.

### Q14: How does the framework prevent an administrator from accidentally locking themselves out?
**Answer:** The user management service enforces an atomic safety invariant: it prevents an administrator from revoking their own `SUPER_ADMIN` role or deactivating their own account if they are the sole active Super Administrator registered in the system.

---

## Domain 4: The 15-Step Invocation Verification Engine

### Q15: List the 15 steps of your verification pipeline in precise sequential order.
**Answer:**
1. Ingestion & Header Normalization
2. Syntactic Payload Validation
3. Client Provenance & IP Reputation Check
4. Cryptographic Identity & JWT Validation
5. Account State & Session Freshness
6. RBAC Role Scope & Permission Evaluation
7. Deep Payload Sanitization (SQLi/XSS/CMDi)
8. Function Lifecycle Status Verification
9. Sliding-Window Rate Limiting & Concurrency
10. Markov State Machine Sequence Verification
11. Least-Privilege Scope Evaluation
12. Dynamic Composite Risk Calculation
13. Policy Evaluation Engine (Allow / Deny)
14. SHA-256 Chained Hash Audit Ledger Write
15. Real-Time Telemetry & SSE Dispatch

### Q16: Why is Step 7 (Payload Sanitization) placed before Step 10 (Markov Sequence Verification)?
**Answer:** Input validation and injection detection are fast, deterministic heuristic operations ($380\mu\text{s}$) that do not require state transitions. If an attacker submits a malformed or malicious payload, it is rejected immediately at Step 7, avoiding unnecessary state transitions or polluting the Markov state history.

### Q17: What is the measured latency of your 15-step pipeline, and how does it relate to *BAMBDA*?
**Answer:** Local workspace measurements on Node.js Express + `node:sqlite` yielded **0.586 ms mean** (median 0.499 ms, p95 0.822 ms) across 200 isolated pipeline calls and **1.741 ms mean** (median 1.535 ms) across 20 live `POST /api/v1/verify/invoke` HTTP requests. Rather than claiming an invented millisecond figure for *BAMBDA*, we cite Shin et al.'s published metric (**8.12% warm-start execution overhead**) and differentiate our architecture by synchronous in-line perimeter enforcement.

### Q18: What is Function Lifecycle Verification (Step 8), and what states are supported?
**Answer:** Serverless functions undergo continuous lifecycle changes. Supported states are:
- `ACTIVE`: Normal operational state; invocations permitted.
- `INACTIVE`: Function temporarily disabled for maintenance; invocations rejected (HTTP 503).
- `DEPRECATED`: End-of-life function; invocations rejected with migration notices (HTTP 410).
- `QUARANTINED`: Function isolated due to active security incident or detected vulnerability; all invocations blocked immediately (HTTP 403).

### Q19: What is the difference between `ENFORCING` and `PERMISSIVE` policy modes in Step 13?
**Answer:**
- In `ENFORCING` mode, if the composite risk score exceeds the threshold ($R \ge 60$) or an anomaly is detected, the pipeline blocks execution (returns HTTP 403/429) and logs an incident.
- In `PERMISSIVE` mode (audit-only/dry-run), the pipeline logs the threat, flags the audit record, and calculates risk, but allows the invocation to proceed. This allows administrators to benchmark security policies without risking production downtime.

---

## Domain 5: Threat Detection & Mathematical Risk Scoring

### Q20: What are the 10 canonical threat categories detected by your engine?
**Answer:**
1. `UNAUTHORIZED_INVOCATION`
2. `PRIVILEGE_ESCALATION`
3. `EXCESSIVE_PERMISSIONS`
4. `SUSPICIOUS_FREQUENCY`
5. `REPEATED_AUTH_FAILURES`
6. `MALFORMED_PAYLOAD`
7. `POLICY_VIOLATION`
8. `UNUSUAL_ACCESS_PATTERN`
9. `DISABLED_FUNCTION_ACCESS`
10. `REPEATED_DENIED_OPS`

### Q21: Explain the mathematical formula used to compute the composite risk score $R$.
**Answer:**
$$R = \min\left(100, \, \max_{k \in \mathcal{A}} \Big( B_k \times W_{\text{env}} \Big) + \sum_{j \in \mathcal{A}} \Delta_j + \delta_{\text{velocity}}\right)$$
- $\mathcal{A}$: Set of triggered rule alerts for the invocation.
- $B_k$: Base severity score for threat category $k$ (e.g., Critical = 90, High = 75).
- $W_{\text{env}}$: Environmental multiplier ($1.2$ for Production, $1.0$ for Staging, $0.8$ for Dev).
- $\Delta_j$: Additive penalty for secondary concurrent infractions.
- $\delta_{\text{velocity}}$: Denial velocity penalty calculated as $\min(25, 5 \times D_{120})$, where $D_{120}$ is the count of denied requests from this client in the past 120 seconds.

### Q22: How does deterministic workflow sequence validation work, and what threat does it prevent?
**Answer:** In multi-stage cloud workflows, business functions must be invoked in a defined order (e.g., `authenticate` $\to$ `fetchOrder` $\to$ `processPayment`). Attackers attempt to bypass intermediate controls by directly calling high-value functions (e.g., `processPayment`).
Rather than using probabilistic models, our framework enforces deterministic rule-based sequence validation via the `function_rules` relational table: each registered function declares explicit predecessor/transition rules (`require_previous_function`, allowed source triggers). If an invocation attempts an unauthorized or out-of-order transition, Step 10 flags an `UNUSUAL_ACCESS_PATTERN` violation and blocks the request.

### Q23: How does your sliding-window rate limiter work without leaking memory over time?
**Answer:** Instead of fixed-interval counters that suffer from boundary burst attacks (double quota at minute boundaries), we implement a sliding-window log:
1. Each client maintains an array of recent invocation timestamps.
2. Prior to evaluation, timestamps older than $T_{\text{now}} - \text{WindowSize}$ (e.g., 60 seconds) are evicted.
3. The remaining count is evaluated against the rate limit. Memory is bounded because inactive clients are evicted from memory during periodic garbage collection sweeps.

---

## Domain 6: Cryptographic Audit Logging & Incident Management

### Q24: How does your tamper-evident audit ledger detect historical record modification?
**Answer:** Each audit entry $k$ is cryptographically linked to its predecessor using sequential SHA-256 hash chaining:
$$H_k = \text{SHA256}\Big( R_k \,\|\, H_{k-1} \Big)$$
where $R_k$ is the canonical serialized record payload ($T_k, U_k, A_k, R_k, D_k, S_k$) and $H_{k-1}$ is the hash of the preceding log entry. Because $H_k$ depends on $H_{k-1}$ and all record attributes, any modification of a historical record changes its computed hash, causing a deterministic mismatch with $H_{k+1}$ and all subsequent records.

### Q25: How does the `verifyAuditLogIntegrity()` function detect which record was tampered with?
**Answer:** The verification function performs a chronological pass:
1. Sets expected previous hash $H_{\text{prev}} = H_0$ (the genesis seed).
2. For each row $k$, recomputes $\hat{H}_k = \text{SHA256}(\text{payload}_k \,\|\, H_{\text{prev}})$.
3. Checks if $\hat{H}_k == H_k$.
4. If a discrepancy is found, it terminates and outputs the exact ID, timestamp, and tampered field values of the compromised record.

### Q26: Explain the incident lifecycle state machine.
**Answer:**
- `OPEN`: Automatically triggered by the threat engine when risk score $\ge 75$ or on critical threats.
- `INVESTIGATING`: Claimed or assigned to a Security Analyst; forensic logs undergoing review.
- `MITIGATED`: Temporary controls applied (e.g., token revoked, IP rate-limited).
- `RESOLVED`: Underlying vulnerability or policy gap patched.
- `CLOSED`: Formal post-mortem completed and signed off into the tamper-evident audit ledger.

### Q27: How does alert deduplication prevent security analyst alert fatigue?
**Answer:** When a threat is detected, the engine queries the `security_incidents` table for any open incident with matching `affected_resource` and `threat_category` created within the last 15 minutes. If a match is found, the new alert is appended to that existing incident's evidence bundle rather than generating a duplicate incident ticket.

---

## Domain 7: Real-Time Telemetry & System Architecture

### Q28: Why did you choose Server-Sent Events (SSE) instead of WebSockets for real-time monitoring?
**Answer:**
1. **Unidirectional Simplicity**: Security telemetry flows unidirectionally from the edge verification engine to the browser SOC dashboard. Full-duplex WebSockets add unnecessary protocol overhead.
2. **HTTP/2 Multiplexing**: SSE runs over standard HTTP/2, sharing single TCP connections with existing REST requests.
3. **Edge Worker Compatibility**: SSE works seamlessly with edge streaming responses (`TransformStream`) without needing complex stateful WebSocket session persistence across distributed edge regions.
4. **Built-in Auto-Reconnect**: The browser's native `EventSource` API handles reconnections automatically.

### Q29: What happens if a client's corporate network blocks SSE connections?
**Answer:** The frontend `useRealtimeStream` hook detects SSE connection failures. If the stream fails to establish within a timeout or returns an error, it gracefully degrades to **Adaptive Polling**, querying `/api/system/overview` and `/api/incidents` every 3 seconds. When network conditions improve, it automatically attempts to re-establish the push stream.

### Q30: How does Cloudflare D1 ensure data persistence and query performance?
**Answer:** Cloudflare D1 is a serverless relational database built on SQLite. It provides full ACID transaction guarantees and sub-millisecond read latency by deploying read replicas close to edge nodes, while serializing writes through a primary leader region. Every query in our framework uses parameterized prepared statements (`db.prepare().bind()`), ensuring fast query plan caching and immunity to SQL injection.

---

## Domain 8: Testing, Verification & Defense Strategy

### Q31: How many automated tests exist in your test suite, and what is the pass rate?
**Answer:** The test suite contains **44 automated test cases/sections** across **6 dedicated suites** (`auth-security.test.ts`, `rbac-security.test.ts`, `verification-pipeline.test.ts`, `security-hardening.test.ts`, `identity-credentials-workflow.test.ts`, and `migration-and-hardening.test.ts`), executing via `npm test` with a **100% pass rate (44 / 44)**.

### Q32: How did you test SQL injection resilience?
**Answer:** We submitted SQL injection payloads (`' OR '1'='1`, tautologies, union probes) to the 15-step threat scanner and verified that all SQLite and Worker D1 database queries use parameterized prepared statements (`db.prepare().bind()`), treating inputs strictly as bound data.

### Q33: How did you test Cross-Site Scripting (XSS) & Command Injection resilience in the payload inspector?
**Answer:** Payloads containing shell injection commands (`; /bin/sh`), IMDS SSRF URLs (`169.254.169.254`), prompt injection, SQLi, and insecure deserialization were tested in `test/security-hardening.test.ts` and `test/verification-pipeline.test.ts` and consistently denied fail-closed.

### Q34: What is the Developer Workbench, and how does it support policy simulation?
**Answer:** The Developer Workbench is an interactive testing environment within the frontend that allows developers and security teams to inspect active tokens and execute test invocations against `/api/v1/verify/invoke`, observing real-time verification latency, risk scoring, and decision gates.

### Q35: If an examiner asks: "Is your system really real-time if live HTTP verification averages 1.74 ms?", how do you answer?
**Answer:** Yes. Core 15-step verification averages **0.586 ms** isolated and **1.741 ms** across the full HTTP + SQLite audit path—well under human perceptual latency (100 ms) and synchronous *before* handler execution rather than waiting on asynchronous post-hoc log ingestion.

### Q36: How does the framework prevent false positives on legitimate traffic?
**Answer:** Authorized calls with valid claims, permitted RBAC roles, valid workflow transitions, and normal request rates pass Steps 1–13 with base risk scores below `maxRiskThreshold` (default 75%), as verified in Scenario 1 of `test/verification-pipeline.test.ts` and live HTTP testing.

### Q37: How do you protect against brute-force password guessing and MFA guessing?
**Answer:** Both login (`max 5 failures`) and per-challenge MFA verification (`max 5 attempts` in `mfa_challenges`, atomically locked at `consumed = 1`) enforce strict attempt caps and rate limiting, locking out repeated guesses before token issuance.

### Q38: What external dependencies are required to run this framework locally?
**Answer:** The local Node.js runtime relies on built-in `node:sqlite`, Express, React 19, Vite, and TypeScript (`tsx`). The Cloudflare Worker script (`src/worker.ts`) uses pure Web Crypto (`crypto.subtle`) and D1 prepared statements, and was verified locally against a `node:sqlite` D1 adapter (remote Cloudflare D1 deployment requires external Cloudflare API credentials).

### Q39: Can your framework be deployed across Express Node.js and Cloudflare Workers?
**Answer:** Yes. Core verification, strict HS256 JWT validation, PBKDF2-SHA512 hashing, and recovery-code / TOTP MFA are implemented in parity across Express (`server/`) and the Web Fetch Worker (`src/worker.ts`), with local validation via an async SQLite D1 adapter.

### Q40: What are the primary academic contributions of this capstone project?
**Answer:**
1. Demonstrating synchronous 15-step in-line security verification in **0.586 ms** (pipeline) / **1.741 ms** (full HTTP API) prior to serverless handler execution.
2. Designing and verifying a **laptop-only SHA-256 recovery-code MFA workflow** (atomic transaction & D1 CAS concurrency controls) alongside optional RFC 6238 TOTP so users never depend on mobile phones or unconfigured SMS gateways.
3. Integrating **tamper-evident SHA-256 hash chaining** and fail-closed containment (`DENY` on pipeline fault, `503` on missing D1 binding).
4. Validating the complete architecture across **44 automated tests in 6 suites**.

### Q41: How do you handle clock drift between edge nodes and authenticator apps for TOTP?
**Answer:** The optional RFC 6238 TOTP mode uses 30-second steps checking $C_0$, $C_{-1}$, and $C_{+1}$ while blocking step replay via `last_totp_step`. Users without an authenticator app use laptop-only recovery codes with zero clock sensitivity.

### Q42: Summarize your capstone project in two sentences for the external examiner.
**Answer:** "We designed and implemented an integrated real-time security verification framework that enforces a 15-step in-line defense pipeline prior to serverless handler execution, measuring 0.586 ms isolated overhead and 1.741 ms full HTTP latency. Grounded in comparative analysis against IEEE Access *BAMBDA* [1], it delivers PBKDF2-SHA512 security, laptop-accessible recovery-code MFA plus optional TOTP, strict HS256 JWT checks, RBAC, deterministic sequence validation, and SHA-256 hash-chained audit logging verified across 44 automated tests."
