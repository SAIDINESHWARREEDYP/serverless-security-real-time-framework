# Threat Model & Attack Surface Analysis

**Project**: Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications  
**Publication Target**: IEEE Access / Bλambda Foundation (B.Tech CSE Capstone 2026–2027)  
**Standard Followed**: Microsoft STRIDE & OWASP Top 10 Serverless (2025/2026 Editions)  
**Document Status**: APPROVED — ARCHITECTURE PHASE 2  

---

## 1. System Scope & Trust Boundaries

The system protects ephemeral, event-driven serverless cloud workloads against external adversaries, compromised dependencies, and insider threats.

```
                    TRUST BOUNDARY 0: Public Internet
                                    │
                       (Untrusted Client Requests)
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │   TRUST BOUNDARY 1: Edge Ingress & Verification Layer   │
       │   - Cloudflare Worker / Reverse Proxy Sidecar           │
       │   - Token Signature & Invalidation Check                │
       │   - In-flight Parameter & Anomaly Engine                │
       └────────────────────────────┬────────────────────────────┘
                                    │ (Verified & Sanitized Calls)
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │   TRUST BOUNDARY 2: Execution Runtime                   │
       │   - Ephemeral Serverless Containers (Node.js/Python)    │
       │   - Upstream Microservices / Functions                  │
       └────────────────────────────┬────────────────────────────┘
                                    │ (Encrypted TLS & Auth)
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │   TRUST BOUNDARY 3: Persistent Data Layer               │
       │   - Cloudflare D1 (SQLite Edge Engine)                  │
       │   - Immutable Audit Logs & Hash Chain                   │
       └─────────────────────────────────────────────────────────┘
```

---

## 2. STRIDE Threat Categorization

| STRIDE Category | Specific Serverless Attack Vector | Impact Level | Architectural Mitigation |
| :--- | :--- | :--- | :--- |
| **S - Spoofing** | Forged JWT tokens, algorithm switching (`none` attack), identity impersonation | **CRITICAL** | Cryptographic verification via HMAC-SHA256 with strong secrets; strict rejection of unapproved algorithms; dynamic claims validation (`iss`, `aud`, `exp`). |
| **T - Tampering** | Parameter manipulation, payload tampering in transit, out-of-order execution sequence | **HIGH** | SHA-256 payload integrity hashing; strict JSON schema bounds checking; state machine sequence verification. |
| **R - Repudiation** | Malicious invocations denying responsibility, log deletion or falsification | **HIGH** | Write-only append audit log in D1; cryptographic hash chaining of event records ($H_n = \text{SHA256}(H_{n-1} + \text{Event}_n)$); automated timestamps. |
| **I - Information Disclosure** | Server-Side Request Forgery (SSRF) targeting Cloud Metadata Services (`169.254.169.254`), container credential exfiltration | **CRITICAL** | Regex and IP canonicalization engine blocking IPv4/IPv6/Hex/Octal IMDS endpoints; environment variable scrubbing. |
| **D - Denial of Service** | Denial-of-Wallet (algorithmic complexity attacks, recursive invocations, runaway lambdas) | **HIGH** | Edge rate limiting per client IP and authenticated user; invocation depth counters; payload size caps (512 KB); execution timeouts (5000 ms). |
| **E - Elevation of Privilege** | Horizontal privilege escalation (IDOR), vertical privilege escalation (bypassing Admin UI to hit admin endpoints) | **CRITICAL** | Server-side RBAC validation at every API route; session state queries in D1; role switching disabled in production. |

---

## 3. Serverless-Specific Attack Vectors & In-Depth Mitigations

### 3.1 Cloud Metadata Exfiltration (SSRF via IMDS)
- **Vector Description**: Serverless functions running inside AWS Lambda, Google Cloud Run, or Azure Functions inherit ephemeral IAM roles. Attackers inject URLs or parameters causing the function to fetch credentials from the Instance Metadata Service (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`).
- **Obfuscation Variants Handled**:
  - Direct IP: `http://169.254.169.254`
  - Hex Encoded: `http://0xa9.0xfe.0xa9.0xfe`
  - Dword / Integer: `http://2852039166`
  - Octal Encoded: `http://0251.0376.0251.0376`
  - IPv6-Mapped IPv4: `http://[::ffff:169.254.169.254]`
  - DNS Rebinding / Hostname: `http://metadata.google.internal/`
- **Mitigation**: The verification engine intercepts and decodes all URL parameters, headers, and request bodies before execution. Any match against the IMDS regex dictionary results in immediate termination with HTTP `403 Forbidden` and creates a **Critical Risk** security alert.

### 3.2 State Machine & Sequence Deviation (Event-Flow Tampering)
- **Vector Description**: Serverless microservices rely on choreographed invocation chains (e.g., `OrderPlaced` $\rightarrow$ `InventoryReserved` $\rightarrow$ `PaymentCharged` $\rightarrow$ `ReceiptIssued`). An adversary attempts to trigger `PaymentCharged` directly or invoke high-privilege processing functions without preceding authorization events.
- **Mitigation**:
  - Each invocation must carry a verified parent trace ID and transition token.
  - The framework validates the transition against the stored **Invocation Graph** in the `policies` table.
  - An unauthorized graph leap raises a **Sequence Deviation** anomaly, halting downstream execution.

### 3.3 Revoked Session Replay (Stateless Token Window)
- **Vector Description**: Standard stateless JWT tokens remain valid until their expiration timestamp (`exp`), leaving a vulnerability window of 15 to 60 minutes after an administrator revokes a compromised account.
- **Mitigation**:
  - Hybrid verification: Edge proxy performs local cryptographic signature check, followed by a fast D1 sub-millisecond query:
    ```sql
    SELECT status FROM sessions WHERE session_token = ? AND status = 'active';
    ```
  - Instant Revocation Endpoint: `/api/auth/revoke-session` marks `status = 'revoked'` in D1. Subsequent attempts using that token fail immediately across all edge nodes.

### 3.4 Command & Process Injection in Ephemeral Containers
- **Vector Description**: Ephemeral containers often contain system utilities (`/bin/sh`, `curl`, `node`). Unsanitized input passed to child processes allows attackers to execute shellcode or open reverse shells.
- **Mitigation**:
  - Deterministic regex matchers inspect input for system binary references, command delimiters (`;`, `&&`, `||`, `|`, backticks, `$()`), and base64-encoded shell strings.
  - Strict parameter type casting against predefined schemas.

### 3.5 Prompt Injection in Serverless AI Microservices
- **Vector Description**: Serverless pipelines calling LLM backends are vulnerable to system prompt overrides, delimiter cracking, and context escape attempts.
- **Mitigation**:
  - Specialized heuristic scanner detects adversarial markers (`"Ignore previous instructions"`, `"[SYSTEM]"`, `"DAN Mode"`, `"<\|im_start\|>"`).
  - Flags payloads targeting AI processing routes with a high-severity threat alert.

---

## 4. Fail-Closed Architectural Guarantee

A foundational principle of this security framework is **Fail-Closed**:

$$\text{Verdict} = \begin{cases} 
\text{ALLOW} & \text{if and only if all security checks evaluate to PASS} \\
\text{DENY} & \text{if any rule triggers OR if an unhandled runtime error occurs}
\end{cases}$$

### Implementation Mechanism:
```typescript
try {
  // 1. Structure Check
  // 2. Authentication Check
  // 3. Session Revocation Check
  // 4. RBAC Permission Check
  // 5. Threat Pattern Scan
  // 6. Invocation Graph Verification
  return evaluateFinalVerdict(riskScore, checks);
} catch (unhandledException) {
  // Fail-closed enforcement: Never allow execution to proceed on failure
  await auditLogSecurityException(unhandledException, req);
  return res.status(403).json({
    error: 'SECURITY_VERIFICATION_EXCEPTION',
    message: 'Fail-closed defense: Request blocked due to pipeline verification anomaly',
    riskScore: 100,
    decision: 'DENY',
    traceId: req.traceId
  });
}
```

---

## 5. Security Incident Escalation & Response Matrix

| Risk Level | Composite Score Range | System Action | Notification Channel | SLA for Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **Informational** | 0 – 20% | Log and Allow | Audit Stream | None required |
| **Low** | 21 – 40% | Log and Allow | Audit Stream | 48 Hours |
| **Medium** | 41 – 74% | Allow with Taint Flag & Extra Telemetry | Security Dashboard Alert | 8 Hours |
| **High** | 75 – 89% | Block (HTTP 403) & Log Incident | Real-time SSE Alert | 1 Hour |
| **Critical** | 90 – 100% | Block (HTTP 403), Session Termination, Threat IP Quarantine | High-Priority Security Incident | Immediate (< 15 mins) |
