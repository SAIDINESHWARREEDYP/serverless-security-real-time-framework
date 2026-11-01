# PRIORITIZED IMPLEMENTATION ROADMAP

**Project:** Serverless Security Verification Framework  
**Target:** Final-Year B.Tech CSE Capstone Project (2026–2027)  
**Execution Objective:** Elevate the framework from prototype grade (77/100) to production-hardened, defense-in-depth excellence (100/100).  

---

## Roadmap Overview: Phased Strategy

```
Phase 1 (Complete)   ──▶   Phase 2 (Immediate)  ──▶   Phase 3 (Persistence) ──▶   Phase 4 (Edge Parity) ──▶   Phase 5 (Testing & Viva)
Workspace Audit            Security Hardening         SQLite Database             Cloudflare Worker           Automated Test Suite
Documentation Files        Auth, RBAC, HMAC JWT       Local File Persistence      Full Endpoint Sync          Academic Demo Scripts
```

---

## Phase 2: Immediate Security Hardening & Zero-Trust Perimeter Defense

### Objective
Eliminate all Critical and High security vulnerabilities in authentication, authorization, and administrative API routes.

### Tasks
1. **Implement `requireAdminAuth` Middleware in `server.ts`:**
   - Protect all administrative endpoints:
     - `POST /api/system/policy-config`
     - `POST /api/system/reset`
     - `POST /api/system/clearLogs`
     - `POST /api/system/users`
     - `POST /api/system/users/approve`
     - `POST /api/system/users/reject`
     - `POST /api/system/users/batch-seed`
     - `DELETE /api/system/users/:username`
     - `PATCH /api/system/users/:username`
     - `POST /api/system/rules`
     - `DELETE /api/system/rules/:id`
   - Validate Bearer token signature, check revocation state, and ensure `user.role === 'Admin'`. Return HTTP 403 Forbidden on violation.

2. **Cryptographic JWT Token Generation & Verification:**
   - Replace pseudo-token strings with real RFC-7519 HMAC-SHA256 (`HS256`) signed JWT tokens using a server-side secret (`JWT_SECRET`).
   - Include standard claims: `sub` (username), `role`, `iss` (`serverless-security-framework`), `iat`, `exp` (1 hour), and `jti` (unique token ID).
   - Verify signatures cryptographically on all authenticated endpoints.

3. **Eradicate Universal Password Bypass & Implement Password Hashing:**
   - Remove hardcoded string comparisons (`'ZeroTrust_2026'`, `'MBU_Project_2027'`) in `/api/login`.
   - Store passwords as salted hashes (using Node's built-in `crypto.scrypt` or `crypto.pbkdf2Sync` to avoid external native binary dependencies).
   - Sanitize user objects before returning `/api/system/overview` so `password_hash` is never transmitted to the browser.

4. **Authentication Rate Limiting:**
   - Implement an IP-based sliding window rate limiter on `/api/login` and `/api/auth/mfa/send-sms` (maximum 5 attempts per minute).

---

## Phase 3: Persistent Relational Database (Cloudflare D1 Local Emulation)

### Objective
Replace volatile in-memory JavaScript heap storage with persistent SQLite database storage to guarantee non-repudiation of audit records and survivability across server restarts.

### Tasks
1. **File-Backed SQLite Integration in `server/db.ts`:**
   - Bind `server/db.ts` to a local SQLite database file (`.data/security_framework.db`) or file-synced JSON/SQLite persistence.
   - On server startup, automatically execute `migrations/0001_initial_schema.sql` if the tables do not exist.
   - Ensure all write operations (`INSERT INTO audit_events`, `UPDATE active_sessions`, `INSERT INTO users`) are written to disk synchronously.

2. **Database Integrity & Constraints Verification:**
   - Enforce FOREIGN KEY and UNIQUE constraints on `active_sessions`, `function_rules`, and `users`.
   - Verify that restarting the Node server retains all users, Markov rules, and forensic audit logs.

---

## Phase 4: Cloudflare Workers & D1 Edge Runtime Parity

### Objective
Ensure complete feature parity between the Express Node development server (`server.ts`) and the Cloudflare Workers edge script (`src/worker.ts`).

### Tasks
1. **Port Missing Routes to `src/worker.ts`:**
   - Implement `/api/login`, `/api/register`, `/api/auth/status`, `/api/auth/mfa/send-sms`, `/api/auth/mfa/verify`, `/api/system/overview`, and `/api/system/policy-config` in `src/worker.ts`.
   - Ensure all database queries use native Cloudflare D1 `env.DB.prepare(...).bind(...).run()`.
2. **Standardize Response Headers & CORS:**
   - Ensure all edge responses include `X-Verification-Latency-MS`, `X-Security-Verification-Duration-MS`, and `Server-Timing`.
   - Restrict `Access-Control-Allow-Origin` to trusted origins specified by `ZERO_TRUST_ORIGIN`.

---

## Phase 5: Automated Test Suite & Viva Demonstration Assets

### Objective
Provide academic examiners with automated, verifiable proof of all four IEEE Bλambda pillars and zero-trust security guarantees.

### Tasks
1. **Automated Integration Test Runner:**
   - Install Vitest (`npm install -D vitest @types/node`).
   - Add `"test": "vitest run"` script to `package.json`.
2. **Develop Core Test Suites:**
   - `test/fail_closed.test.ts`: Proves that simulated exceptions return HTTP 403 with 100% Risk score and log security exceptions.
   - `test/latency_overhead.test.ts`: Benchmarks 100 concurrent requests, verifying that median verification latency is $< 1.5\text{ms}$.
   - `test/markov_sequence.test.ts`: Proves that sequential transitions (A -> B) pass while out-of-order transitions (A -> D) trigger a $+40\%$ risk penalty.
   - `test/session_revocation.test.ts`: Proves that active tokens are blocked immediately after `/api/auth/revoke-session` is executed.
   - `test/rbac_enforcement.test.ts`: Proves that non-admin tokens are strictly rejected on administrative routes.
3. **Capstone Demonstration Scripts (`scripts/demo_viva.sh`):**
   - Provide an automated bash/curl script that runs during the live viva examination to demonstrate live attack interception, rate limit burst blocking, and forensic audit ledger export.

---

## Execution Schedule Summary

| Phase | Focus Area | Deliverables | Target Score |
| :--- | :--- | :--- | :--- |
| **Phase 1 (Done)** | Workspace Audit & Architecture Inventory | 6 Audit Markdown Reports | 77 / 100 |
| **Phase 2** | Security Hardening & Zero-Trust Perimeter | Protected Admin APIs, HMAC JWTs, Hashed Passwords | 88 / 100 |
| **Phase 3** | Database Persistence (D1 Emulation) | Disk-backed SQLite storage, migration auto-runner | 94 / 100 |
| **Phase 4** | Cloudflare Workers Parity | Full API parity in `src/worker.ts` with D1 bindings | 97 / 100 |
| **Phase 5** | Automated Testing & Viva Assets | Vitest test suites, latency benchmarks, viva demo script | **100 / 100** |
