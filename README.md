# Integrated Real-Time Security Verification Framework for Serverless Cloud Applications

[![Zero-Trust Architecture](https://img.shields.io/badge/Architecture-Zero--Trust-blue.svg)](#)
[![TypeScript](https://img.shields.io/badge/Language-TypeScript%205.x-blue)](#)
[![Cloudflare Workers & D1](https://img.shields.io/badge/Runtime-Cloudflare%20Workers%20%2B%20D1-orange)](#)
[![Test Suite](https://img.shields.io/badge/Tests-55%2F55%20Passed%20(100%25)-brightgreen)](#)
[![Security Hardening](https://img.shields.io/badge/Security-Fail--Closed%20%7C%20OWASP%20Top%2010-emerald)](#)

## Overview

The **Integrated Real-Time Security Verification Framework** is an enterprise-grade cloud security platform engineered for serverless microservices and edge compute runtimes. It enforces an in-line **15-Step Security Verification Pipeline** that validates requests before invoking business logic (reproducible `npm run benchmark` measurements: $1.140\text{–}1.300\text{ ms}$ isolated pipeline mean, $1.577\text{–}1.622\text{ ms}$ Express gateway header latency, and $7.088\text{–}7.589\text{ ms}$ end-to-end HTTP round-trip).

---

## Key Features

1. **Zero-Trust Identity Gateway**:
   - PBKDF2 cryptographic password hashing with unique 16-byte random salts (100,000 iterations).
   - HMAC-SHA256 (`HS256`) signed JWT session tokens with strict claim verification (`exp`, `nbf`, `iss`, `aud`, `sub`, `jti`, `iat`).
   - Laptop-accessible multi-factor authentication via atomic, single-use SHA-256 recovery-code enrollment and verification, paired with optional RFC 6238 TOTP (Google/Microsoft Authenticator) with strict clock-drift tolerance (±1 step) and time-step replay prevention.
   - Real-time stateful session revocation with immediate invalidation backed by relational SQL persistence.

2. **Server-Enforced Canonical RBAC**:
   - 6 Canonical roles: Super Administrator, Security Administrator, Security Analyst, Developer, Auditor, Viewer.
   - 21 Granular permissions across 5 security domains.
   - Central authorization service with immutable permission change and access-denied audit trails.

3. **15-Step In-Line Invocation Verification Engine**:
   - Comprehensive request validation, identity claim extraction, role validation, sequence analysis, and risk scoring.
   - Deterministic rule-based workflow transition verification (`function_rules`) to detect and prevent unauthorized lateral movement.
   - High-resolution timing headers: `X-Verification-Latency-MS`, `Server-Timing`, `X-Verification-Decision`, `X-Verification-Risk-Score`.

4. **Multi-Vector Serverless Threat Detection Engine**:
   - Heuristic pattern scanner detecting 6 core serverless attack categories: Cloud Metadata IMDS SSRF (`169.254.169.254`), OS Command/Shell Injection, Adversarial Prompt Injection, Credential Leakage, SQL Injection, and Insecure Deserialization.
   - Guaranteed Zero-Trust fail-closed containment: unhandled exceptions assign 100% Critical Risk and return HTTP 403 Forbidden.

5. **Tamper-Evident SHA-256 Audit Ledger**:
   - Full-ledger cryptographic sequential hash chaining ($H_t = \text{SHA256}(R_t \parallel H_{t-1})$) anchored to a trusted 64-zero genesis hash (`TRUSTED_AUDIT_GENESIS_HASH`) and HMAC-SHA256 sealed head checkpoint (`audit_chain_anchor`) with live server-side verification (`GET /api/v1/audit/verify-chain`) on both Express and Cloudflare Worker.
   - Real-time Server-Sent Events (SSE) live streaming with automatic reconnection, missed-event polling fallback, and cross-mode deduplication.
   - Client-side structured JSON download of audit logs with metadata, filters, and statistics.
   - Full incident response lifecycle management (Open, Investigating, Contained, Resolved).

6. **Interactive Zero-Trust Frontend**:
   - Command Center, Interactive Security Timeline, Function Inventory, Invocation Explorer, 15-Step Pipeline Trace Viewer, Threat Center, Incident Console, User Database, RBAC Console, Policy Management, Simulation Workbench, and Health & Risk Analytics featuring a 50-log historical risk trend Recharts line graph and a real-time **Threat Heatmap** (`Time × Function` and `Vector × Function` intensity coordinate mapping with forensic drill-down).

---

## Quick Start & Verification

```bash
# 1. Install dependencies
npm install

# 2. Run all 8 automated security test suites (44 baseline + 6 recovery/D1/UI + 5 pre-finalization audit = 55 tests)
npm test

# 3. Run reproducible latency benchmark (isolated SQLite WAL)
npm run benchmark

# 4. Run development server (Port 3000)
npm run dev

# 5. Build for production
npm run build
```

---

## Local Development & Demonstration Configuration

To demonstrate the platform safely without exposing production secrets:

1. Copy `.env.example` to `.env` and set high-entropy values for `JWT_SECRET` (minimum 32 characters) and trusted origins.
2. In local test environments, default test principals (such as `secops_admin` and `cloud_dev`) are seeded in the local SQLite database (`server/data/security_framework.sqlite`).
3. For user registration, supply an explicit password of at least 8 characters. Upon admin approval and first sign-in, the user completes laptop-only single-use recovery-code enrollment (with Copy All and `.txt` download) or optional RFC 6238 TOTP enrollment.
4. Universal demo passwords, shared TOTP seeds, and bypass codes (`12345@pro`, `ZeroTrust_2026`, `JBSWY3DPEHPK3PXP`, `123456`, `847291`) have been eliminated to uphold strict Zero-Trust integrity.

---

## Academic References & Documentation

- **Base Paper:** C. Shin, B. Kim, and S. Lee, "BAMBDA: A Real-Time Verification Framework for Serverless Computing," *IEEE Access*, vol. 13, pp. 90896–90911, 2025. DOI: [10.1109/ACCESS.2025.3572729](https://doi.org/10.1109/ACCESS.2025.3572729).
- [FINAL_PROJECT_REPORT.md](./FINAL_PROJECT_REPORT.md): Comprehensive 23-chapter final capstone thesis
- [FINAL_ABSTRACT.md](./FINAL_ABSTRACT.md): University-compliant final abstract (175 words)
- [SOURCE_TO_CLAIM_VERIFICATION_MATRIX.md](./SOURCE_TO_CLAIM_VERIFICATION_MATRIX.md): Traceability matrix verifying claims against source code
- [BASE_PAPER_VS_PROPOSED_PROJECT_COMPARISON.md](./BASE_PAPER_VS_PROPOSED_PROJECT_COMPARISON.md): Detailed comparison against Shin et al.
- [CITATION_AND_REFERENCE_AUDIT.md](./CITATION_AND_REFERENCE_AUDIT.md): Complete IEEE citation audit with RFC specifications
- [TEST_RESULTS.md](./TEST_RESULTS.md): Execution logs across all 55 automated tests (44 core + 6 recovery/D1/`ThreatHeatmap`/UI/real-time + 5 pre-finalization verification) and [PERFORMANCE_EVALUATION.md](./PERFORMANCE_EVALUATION.md) (`npm run benchmark`)
- [FINAL_SECURITY_REMEDIATION_REPORT.md](./FINAL_SECURITY_REMEDIATION_REPORT.md): Security audit and remediation verification report
- [FINAL_PROJECT_ACCEPTANCE_REPORT.md](./FINAL_PROJECT_ACCEPTANCE_REPORT.md): Formal capstone acceptance sign-off
- [VIVA_PREPARATION_GUIDE.md](./VIVA_PREPARATION_GUIDE.md): Technical defense questions and answers for external examination
