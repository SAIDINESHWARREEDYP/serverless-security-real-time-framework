# BASE PAPER VS. PROPOSED CAPSTONE PROJECT COMPARISON

**Base Paper:** Changhee Shin, Bom Kim, and Seungsoo Lee, "BAMBDA: A Real-Time Verification Framework for Serverless Computing," *IEEE Access*, vol. 13, pp. 90896–90911, 2025. DOI: [10.1109/ACCESS.2025.3572729](https://doi.org/10.1109/ACCESS.2025.3572729).

**Proposed Capstone:** Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications (B.Tech CSE Capstone 2026–2027).

---

## 1. Dimensional Comparison Matrix

| Dimension | Original BAMBDA Research Paper (Shin et al., IEEE Access 2025) | Proposed Capstone Project (Our System) | Nature of Contribution | Empirical Evidence & References |
|---|---|---|---|---|
| **Primary Research Objective** | Formal runtime verification of safety and liveness properties in serverless workflows via automated code injection and centralized log analysis. | Architectural integration of zero-trust identity, granular RBAC, in-line multi-factor verification, and tamper-evident audit logging for serverless invocations. | **Independent Adaptation & Extension** | Base paper focused on automated property checking [1]; this capstone addresses identity, authorization, and audit integration. |
| **Runtime Target Platform** | Amazon Web Services (AWS Lambda) execution environment. | Hybrid Edge and Microservice runtime: Cloudflare Workers with Cloudflare D1 (edge) and Node.js Express with SQLite (local development/testing). | **Different Platform Architecture** | BAMBDA relies on AWS CloudWatch and AWS Lambda Layers [1]; our system targets edge compute and serverless SQL. |
| **Verification Architecture** | Log-group based automated code injection; centralized logging analysis engine; verifies direct, event-driven, and API Gateway invocations. | Synchronous, in-line 15-step verification pipeline intercepting requests before function handler execution. | **Architectural Divergence** | BAMBDA injects verification instrumentation into Lambda code; our system acts as a front-facing verification gateway/middleware. |
| **Verification Method** | Formal runtime verification against temporal logic / state properties defined per workflow. | Rule-based sequence transition checking (`function_rules`), rate burst frequency analysis, and static heuristic payload scanning. | **Distinct Technical Approach** | BAMBDA evaluates formal temporal formulas [1]; our implementation executes deterministic transition table lookups. |
| **Identity & Authentication** | Delegated entirely to AWS IAM and upstream API Gateway authentication; not an internal focus of BAMBDA. | Full native Zero-Trust identity management: PBKDF2-SHA512 hashing (100,000 rounds), RFC 6238 TOTP MFA, single-use backup codes, and HMAC-SHA256 JWT. | **Original Capstone Implementation** | RFC 6238 [2], RFC 7519 [3], NIST SP 800-207 [4]. Tested in `test/auth-security.test.ts`. |
| **Access Control (RBAC)** | Relies on external cloud provider IAM roles and policies. | Centralized granular RBAC engine: 6 canonical roles, 21 permissions across 5 security domains, privilege escalation prevention, access-denied logging. | **Original Capstone Implementation** | `server/repositories/rbac.repository.ts`, tested in `test/rbac-security.test.ts`. |
| **Threat Vector Detection** | Detects workflow property violations and illegal function execution order. | Heuristic regex/pattern scanner targeting 6 specific serverless attack categories: IMDS SSRF, Shell Injection, Prompt Injection, Credential Leak, SQLi, and Deserialization. | **Extended Application Layer Defense** | OWASP Serverless Top 10 [5]. Tested in `test/security-hardening.test.ts`. |
| **Audit Integrity & Storage** | AWS CloudWatch centralized log groups. | Tamper-evident SHA-256 hash-chained ledger stored in ACID relational tables (`audit_events`) with real-time SSE broadcast. | **Original Design Choice** | Evaluated via automated cryptographic hash chain verification over 100 consecutive records. |
| **Performance Overhead & Baseline** | Reports an empirical overhead of **8.12%** under warm-start conditions in AWS Lambda benchmarks. | Reproducible local micro-benchmark demonstrates mean 15-step in-line evaluation latency of **1.07 ms** (median 1.04 ms, p95 1.20 ms) in Node.js environment. | **Independent Measurement** | BAMBDA measures relative overhead percentage on AWS Lambda [1]; this capstone measures absolute gateway latency in microsecond precision. |

---

## 2. Categorization of Contributions

### A. What Was Adopted from BAMBDA
1. The core research premise that **real-time verification must precede or accompany serverless execution** to prevent state poisoning and out-of-order execution.
2. The concept of tracking function invocation sequences across workflow stages to detect anomalous lateral movement.

### B. What Was Adapted and Modified
1. **Transition Verification**: Instead of BAMBDA's automated AST code injection and AWS CloudWatch log group scraping, our framework implements an in-line edge gateway verification pipeline.
2. **Sequential State Model**: Rather than compiling complex temporal logic assertions, our system uses a deterministic transition lookup table (`function_rules`) that assigns additive risk penalties (+40%) to sequence violations.

### C. What Was Independently Developed (Our Capstone Contributions)
1. **Complete Zero-Trust Authentication Lifecycle**: PBKDF2-SHA512 password hashing with random 16-byte salts, RFC 6238 TOTP MFA with replay prevention, single-use SHA-256 hashed recovery codes, and HS256 JWT tokens.
2. **Stateful Session Revocation**: Immediate edge invalidation persisting across Worker restarts using relational SQL storage.
3. **Multi-Vector Payload Scanning**: Deep inspection of serverless HTTP payloads for cloud metadata exfiltration (AWS/GCP IMDS SSRF `169.254.169.254`), prompt injection, OS commands, credential leaks, SQL injection, and insecure deserialization.
4. **Tamper-Evident SHA-256 Audit Ledger**: Chained hashing verifying ledger integrity, combined with real-time Server-Sent Events (SSE) telemetry and client-side structured JSON export.
5. **Interactive Zero-Trust Management Console**: 26 React frontend interfaces providing complete administrative oversight, simulation sandboxes, and visual trend analytics.

### D. What Was NOT Implemented (Transparent Academic Boundaries)
1. Automated compiler-level code rewriting / AST transformation for arbitrary cloud provider runtimes (BAMBDA's injection mechanism).
2. Probabilistic Markov modeling (DTMC with transition probability matrices); the system uses deterministic rule checking.
3. Merkle tree cryptographic structures or blockchain consensus; the ledger uses sequential SHA-256 chaining.
4. Formal AWS Lambda Layer injection; the system targets Cloudflare Workers and Node.js microservices.

---

## 3. Academic Integrity Summary

Our capstone does not claim to outperform BAMBDA on AWS Lambda; rather, it investigates an alternative architectural question: **Can an in-line, Zero-Trust verification gateway enforce identity, sequence, rate, and payload security on modern serverless edge runtimes with sub-1.5 ms verification overhead?** Our implementation and experimental evidence answer this question affirmatively.
