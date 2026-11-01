# PHASE 13 — Capstone Viva Demonstration Guide

## Complete Step-by-Step Live Demonstration Script

This guide provides the exact demonstration flow for final-year evaluators, thesis committees, and security reviewers.

---

### Step 1: Zero-Trust Gateway Sign In & MFA Verification
1. Navigate to the application root (`/`).
2. Enter username: `secops_admin` and password: `ZeroTrust_2026`.
3. Click **"Verify Identity & Request Gate Clearance"**.
4. The system validates factor 1 (PBKDF2 hash) and transitions to the **Multi-Factor Authentication** screen.
5. Notice the **Active Authenticator Code** displayed (e.g. `107207`), or enter `123456`, or click **"Auto-fill"**.
6. Click **"Confirm & Establish Session"**.
7. System generates a signed HMAC-SHA256 JWT, logs an immutable audit event, and opens the **SecOps Command Center**.

---

### Step 2: Live In-Line 15-Step Verification Inspection
1. In the **Admin Command Center**, locate the **Operational Serverless Function Direct Invocation** panel.
2. Click **"Execute `/api/getDashboardMetrics`"**.
3. Observe the verification result:
   - Status: `ALLOWED`
   - In-Line Verification Latency: $\approx 1.2\text{ ms}$ (displayed in terminal log and HTTP header `X-Verification-Latency-MS`).
4. Click on the resulting entry in the **Audit Log Stream** to open the **15-Step Pipeline Trace Viewer**.
5. Walk the evaluators through each of the 15 distinct steps:
   - Step 1: Payload sanity check
   - Step 3: Cryptographic JWT signature check
   - Step 6: RBAC permission check (`metrics:read`)
   - Step 9: Markov sequence validation
   - Step 14: Tamper-evident SHA-256 hash chaining ($H_t$).

---

### Step 3: Lateral Movement & Markov Sequence Anomaly Drill
1. In the **Security Drills** panel, click **"Run Lateral Movement Drill"**.
2. The drill attempts an invalid invocation sequence (e.g. `auditor_guest` jumping directly to `/api/purgeColdStorageBackups` without preceding authentication sequence).
3. The Markov interceptor instantly identifies the sequence violation:
   - Applies $+40\%$ risk penalty.
   - Blocks the invocation with HTTP 403 Forbidden.
   - Records the event in the audit ledger and timeline with tag `SEQUENCE_VIOLATION`.

---

### Step 4: Real-Time Session Revocation (Immediate Edge Invalidation)
1. Click **"User Database"** in the top navigation or sidebar.
2. Locate user `cloud_dev`.
3. Click the red **"Revoke Session"** button.
4. A confirmation dialog appears: "Are you sure you want to terminate active session for cloud_dev?". Click **"Confirm Revocation"**.
5. The session is immediately revoked in D1 SQLite and session cache.
6. Any subsequent API requests from `cloud_dev` are blocked at Step 7 (`TOKEN_REVOKED`).

---

### Step 5: Fail-Closed Exception Handling Proof
1. Click **"Run Fail-Closed Drill"** in the Command Center.
2. The system simulates a hardware security module (HSM) decryption failure inside the verification pipeline.
3. Observe the response:
   - Handled with zero-trust fail-closed guarantee.
   - Assigned $100\%$ Critical Risk.
   - Returns HTTP 403 Forbidden with trace ID.
   - System remains stable and protected.
