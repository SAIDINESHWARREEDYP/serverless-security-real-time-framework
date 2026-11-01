# REST API Design & Interface Specification

**Project**: Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications  
**Publication Target**: IEEE Access / Bλambda Foundation (B.Tech CSE Capstone 2026–2027)  
**Document Status**: APPROVED — ARCHITECTURE PHASE 2  

---

## 1. Overview & Standard Conventions

All API endpoints follow RESTful design standards, return JSON responses, and enforce strict HTTPS transport security. Every request passing through the verification pipeline receives deterministic diagnostic and timing headers.

### Common Request Headers
| Header | Type | Description | Required |
| :--- | :--- | :--- | :--- |
| `Authorization` | `string` | Format: `Bearer <jwt_token>` | Yes (for protected endpoints) |
| `Content-Type` | `string` | Must be `application/json` | Yes (for POST/PUT/PATCH) |
| `X-Request-ID` | `string` | Optional client-generated correlation ID | Optional |

### Common Response Headers
| Header | Example | Description |
| :--- | :--- | :--- |
| `X-Verification-Decision` | `ALLOW` \| `DENY` | High-level verdict from verification sidecar |
| `X-Verification-Risk-Score`| `14` (0–100) | Computed composite risk percentage |
| `X-Verification-Latency-MS`| `3.82` | Latency incurred by the verification pipeline in ms |
| `Server-Timing` | `auth;dur=1.1, ver;dur=2.2` | W3C Server-Timing metric breakdown |
| `X-Content-Type-Options` | `nosniff` | MIME-type sniffing protection |

---

## 2. Role-Based Access Control (RBAC) Matrix

| Endpoint Group | Method & Route | Admin | Developer | Auditor / Guest | Unauthenticated |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Authentication** | `POST /api/auth/login` | Allowed | Allowed | Allowed | Allowed |
| | `POST /api/auth/register` | Allowed | Allowed | Allowed | Allowed |
| | `POST /api/auth/logout` | Allowed | Allowed | Allowed | Denied |
| | `POST /api/auth/revoke-session` | **Allowed** | Denied (403) | Denied (403) | Denied (401) |
| **Verification & Invocations** | `POST /api/verify/invoke` | Allowed | Allowed | Denied (403) | Denied (401) |
| | `GET /api/invocations` | Allowed | Allowed (Own) | Allowed (Read) | Denied (401) |
| **Policies & Graph** | `GET /api/policies` | Allowed | Allowed (Read) | Allowed (Read) | Denied (401) |
| | `POST /api/policies` | **Allowed** | Denied (403) | Denied (403) | Denied (401) |
| | `PUT /api/policies/:id` | **Allowed** | Denied (403) | Denied (403) | Denied (401) |
| **Audit & Incidents** | `GET /api/audit/events` | Allowed | Denied (403) | Allowed (Read) | Denied (401) |
| | `GET /api/security/alerts` | Allowed | Allowed (Read) | Allowed (Read) | Denied (401) |
| **System Health & D1** | `GET /api/system/health` | Allowed | Allowed | Allowed | Denied (401) |
| | `GET /api/system/d1-latency` | Allowed | Allowed | Allowed | Denied (401) |
| | `GET /api/users` | **Allowed** | Denied (403) | Denied (403) | Denied (401) |

---

## 3. Core API Endpoint Specifications

### 3.1 Authentication

#### `POST /api/auth/login`
Authenticates a user identity and generates a signed session token.
- **Request Body**:
  ```json
  {
    "username": "admin",
    "password": "SecurePassword123!"
  }
  ```
- **Success Response (200 OK)**:
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": "usr_94e201b1",
      "username": "admin",
      "email": "admin@cloudsec.local",
      "roles": ["Administrator"]
    },
    "expiresAt": "2026-10-31T04:30:00.000Z"
  }
  ```
- **Error Responses**:
  - `400 Bad Request`: Missing username or password
  - `401 Unauthorized`: Invalid credentials
  - `429 Too Many Requests`: Account locked due to rate limiting

---

#### `POST /api/auth/revoke-session`
Immediately terminates an active session record in Cloudflare D1. Requires **Administrator** role.
- **Headers**: `Authorization: Bearer <token>`
- **Request Body**:
  ```json
  {
    "username": "guest_user",
    "reason": "Suspected anomalous activity"
  }
  ```
- **Success Response (200 OK)**:
  ```json
  {
    "success": true,
    "message": "Active session for user 'guest_user' has been revoked in D1.",
    "revokedSessionsCount": 1,
    "revocationTimestamp": "2026-10-30T11:30:00.000Z"
  }
  ```
- **Error Responses**:
  - `401 Unauthorized`: Unauthenticated caller
  - `403 Forbidden`: Caller lacks `Administrator` privilege
  - `404 Not Found`: Target user has no active sessions to terminate

---

### 3.2 Real-Time Invocation & Verification Engine

#### `POST /api/verify/invoke`
Intercepts and validates an incoming serverless function call before execution.
- **Headers**:
  - `Authorization: Bearer <token>`
  - `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "functionName": "payment-processing-v2",
    "serviceName": "billing-service",
    "payload": {
      "transactionId": "tx_88301",
      "amount": 250.00,
      "currency": "USD"
    },
    "parentTraceId": "trace_b0193-4921",
    "sourceIp": "198.51.100.45"
  }
  ```
- **Response — Pass / Allow (200 OK)**:
  ```json
  {
    "decision": "ALLOW",
    "riskScore": 8,
    "traceId": "trace_f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "verifiedInMs": 3.42,
    "checks": {
      "tokenValid": true,
      "sessionActive": true,
      "rbacGranted": true,
      "imdsProbeDetected": false,
      "promptInjectionDetected": false,
      "sequenceDeviation": false,
      "shellInjectionDetected": false
    },
    "functionOutput": {
      "status": "PROCESSED",
      "confirmationId": "conf_99341"
    }
  }
  ```
- **Response — Threat Detected / Blocked (403 Forbidden)**:
  ```json
  {
    "decision": "DENY",
    "riskScore": 95,
    "errorCode": "THREAT_IMDS_SSRF_DETECTED",
    "message": "Verification failed: Cloud metadata service (169.254.169.254) probe intercepted.",
    "traceId": "trace_a10b9912-38ff-4100-9901-21398bbfa312",
    "verifiedInMs": 2.15,
    "checks": {
      "tokenValid": true,
      "sessionActive": true,
      "rbacGranted": true,
      "imdsProbeDetected": true,
      "promptInjectionDetected": false,
      "sequenceDeviation": false,
      "shellInjectionDetected": false
    }
  }
  ```

---

### 3.3 Audit & Telemetry APIs

#### `GET /api/audit/events`
Fetches chronologically ordered audit logs with SHA-256 chain verification.
- **Query Parameters**:
  - `limit`: Default `50`, Max `200`
  - `offset`: Default `0`
  - `severity`: Filter by `info`, `warning`, `critical`
  - `action`: Filter by specific action (e.g., `AUTH_SESSION_REVOKED`, `VERIFICATION_BLOCKED`)
- **Success Response (200 OK)**:
  ```json
  {
    "events": [
      {
        "id": "aud_1928374",
        "timestamp": "2026-10-30T11:25:40.120Z",
        "actor": "admin",
        "action": "AUTH_SESSION_REVOKED",
        "target": "user:analyst_01",
        "details": "Administrator terminated active session from IP 192.0.2.14",
        "riskScore": 30,
        "integrityHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    ],
    "totalCount": 1420,
    "chainStatus": "VALID"
  }
  ```

---

#### `GET /api/system/d1-latency`
Returns real-time and historical D1 query execution latencies for system health monitoring.
- **Success Response (200 OK)**:
  ```json
  {
    "currentLatencyMs": 1.84,
    "avgLatencyMs": 2.15,
    "p95LatencyMs": 4.10,
    "p99LatencyMs": 7.30,
    "trend": [
      { "time": "11:20:00", "latencyMs": 1.9 },
      { "time": "11:21:00", "latencyMs": 2.3 },
      { "time": "11:22:00", "latencyMs": 1.7 }
    ],
    "d1Status": "HEALTHY",
    "activeConnections": 12
  }
  ```

---

## 4. Standard Error Codes & Structure

All client and server errors adhere to RFC 7807 (Problem Details for HTTP APIs):

```json
{
  "type": "https://serverless-securityverification.ai.studio/errors/AUTH_TOKEN_REVOKED",
  "title": "Token Revoked",
  "status": 401,
  "detail": "The presented session token was revoked by an administrator at 2026-10-30T11:30:00Z.",
  "instance": "/api/verify/invoke",
  "errorCode": "AUTH_TOKEN_REVOKED",
  "traceId": "trace_77401-9921"
}
```

| HTTP Status | Error Code | Description |
| :---: | :--- | :--- |
| `400` | `INVALID_PAYLOAD_SCHEMA` | Malformed JSON or fields violating schema boundaries |
| `401` | `AUTH_TOKEN_EXPIRED` | JWT signature is valid but expiration timestamp passed |
| `401` | `AUTH_TOKEN_REVOKED` | Token revoked in D1 session database |
| `401` | `AUTH_SIGNATURE_INVALID` | Signature mismatch or altered payload |
| `403` | `RBAC_PERMISSION_DENIED` | Identity authenticated but lacks required permission |
| `403` | `THREAT_IMDS_SSRF_DETECTED` | Request intercepted due to cloud metadata address probe |
| `403` | `THREAT_SHELL_INJECTION` | Command execution attempt detected |
| `403` | `SEQUENCE_DEVIATION_DETECTED` | Function invocation violated graph policy order |
| `403` | `SECURITY_VERIFICATION_EXCEPTION`| Unhandled pipeline exception (Fail-Closed triggered) |
| `413` | `PAYLOAD_TOO_LARGE` | Invocation body exceeds 512 KB limit |
| `429` | `RATE_LIMIT_EXCEEDED` | Request frequency exceeded token bucket rate |
| `500` | `INTERNAL_GATEWAY_ERROR` | Cloudflare Worker / Express internal fatal error |
