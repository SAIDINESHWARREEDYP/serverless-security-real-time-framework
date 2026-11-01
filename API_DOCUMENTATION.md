# Serverless Security Verification Framework — Complete API Documentation

**Base URLs**:
- Edge Root: `https://serverless-securityverification.ai.studio`
- Master Versioned Prefix: `/api/v1`
- Legacy & Backward-Compatible Prefix: `/api`

---

## 1. Authentication & Session Endpoints

### `POST /api/v1/auth/login` (also `/api/login`)
Authenticates caller credentials using PBKDF2 verification. If MFA is required, returns challenge; otherwise generates JWT.
- **Rate Limit**: 5 attempts per 300 seconds per IP/account.
- **Request Body**:
  ```json
  {
    "username": "secops_admin",
    "password": "ZeroTrust_2026",
    "totpCode": "311044"
  }
  ```
- **Success Response (200 OK)**:
  ```json
  {
    "success": true,
    "token": "eyJhbGciOi...",
    "session": {
      "user": { "username": "secops_admin", "role": "Super Administrator" },
      "expiresInSeconds": 3600
    }
  }
  ```

### `POST /api/v1/auth/mfa/verify` (also `/api/auth/mfa/verify`)
Verifies RFC 6238 TOTP 6-digit challenge code.
- **Request Body**: `{ "mfaSessionId": "mfa_...", "code": "123456" }`

### `POST /api/v1/auth/revoke-session` (also `/api/auth/revoke-session`)
Terminates an active session in Cloudflare D1 database.
- **Authorization**: Required (`Admin` or `Super Administrator` / `Security Administrator`).
- **Request Body**: `{ "username": "cloud_dev", "reason": "Security review" }`

---

## 2. Serverless Invocation Verification Engine

### `POST /api/v1/verify/invoke`
Executes the full 15-step serverless verification pipeline on incoming operational requests.
- **Headers**:
  - `Authorization: Bearer <jwt_token>`
  - `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "functionName": "getDashboardMetrics",
    "payload": { "filter": "1h" }
  }
  ```
- **Security Telemetry Response Headers**:
  - `X-Verification-Decision`: `ALLOW` | `DENY` | `QUARANTINE`
  - `X-Verification-Risk-Score`: Calculated score `0`–`100`
  - `X-Verification-Latency-MS`: Pipeline duration (e.g., `0.320`)
  - `X-Audit-Record-Id`: Monotonic audit event ID
  - `Server-Timing`: High-resolution microsecond breakdown
- **Success Response (200 OK)**:
  ```json
  {
    "success": true,
    "decision": "ALLOW",
    "riskScore": 15,
    "targetFunction": "getDashboardMetrics",
    "steps": [ ... 15 verified steps ... ],
    "auditRecordId": 142,
    "auditHash": "7f83b165...",
    "verifiedInMs": 0.312
  }
  ```
- **Blocked Response (403 Forbidden)**:
  ```json
  {
    "success": false,
    "decision": "DENY",
    "riskScore": 95,
    "denialReasons": ["Cloud Metadata / SSRF probe targeting IAM credentials."],
    "threatVector": { "threatDetected": true, "threatCategory": "CLOUD_METADATA_SSRF" }
  }
  ```

---

## 3. RBAC & Identity Governance Endpoints

### `GET /api/v1/rbac/roles`
Returns all 6 canonical roles with clearance tiers.

### `GET /api/v1/rbac/permissions`
Returns all 21 granular permissions categorized across Identity, Policy, Execution, Telemetry, and Security.

### `GET /api/v1/rbac/matrix`
Returns the 6-role $\times$ 21-permission assignment matrix.

### `POST /api/v1/rbac/assign`
Reassigns a principal's clearance role.
- **Protection**: Self-escalation blocked, Super Admin promotion guarded.
- **Request Body**:
  ```json
  {
    "targetUsername": "cloud_dev",
    "newRole": "Security Analyst",
    "reason": "Quarterly certification elevation"
  }
  ```

### `GET /api/v1/rbac/access-denied`
Returns the ledger of recorded unauthorized access attempts, IDOR probes, and blocked privilege escalations.

---

## 4. System Health & D1 Telemetry Endpoints

### `GET /api/system/health`
Returns real-time health indicator metrics for Cloudflare D1 connection, active query latency, cluster PoP location, and uptime.
- **Response**:
  ```json
  {
    "status": "UP",
    "cluster": "Cloudflare Global Edge PoP (ap-south-1)",
    "databaseEngine": "Cloudflare D1 Relational Engine (ACID)",
    "databaseConnection": "ACTIVE",
    "d1LatencyMs": 0.285,
    "isConnected": true,
    "recordsVerified": 142
  }
  ```

### `GET /api/system/d1-latency`
Returns statistical database query latency distribution ($P_{50}$, $P_{95}$, $P_{99}$) and active connection pools.
