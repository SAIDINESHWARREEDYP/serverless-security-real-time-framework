# Threat Detection & Risk Analysis Engine

## 1. Architectural Overview & Design Philosophy

The Threat Detection Engine in the Serverless Security Verification Framework operates as an autonomous, multi-layered threat evaluation subsystem integrated directly into the in-line invocation pipeline. Rather than relying on post-hoc log scanning or external SIEM collectors, threat analysis occurs during the execution lifecycle of every invocation request.

The system combines:
1. **Deterministic Rule Matching**: Static policy and pattern matching with sub-millisecond evaluation time.
2. **Dynamic Sliding-Window Behavioral Analysis**: Real-time frequency counting, failure rate monitoring, and concurrent burst detection.
3. **Discrete Markov Chain Sequence Verification**: Transition matrix verification across invocation state sequences to detect unauthorized workflow steps or out-of-order execution.
4. **Heuristic & Signature Payload Inspection**: Context-aware regex signatures for SQL injection (SQLi), Cross-Site Scripting (XSS), Command Injection (CMDi), and Server-Side Request Forgery (SSRF).

---

## 2. The 10 Canonical Threat Categories

Every anomaly or malicious event evaluated by the engine is mapped to one of 10 standard security categories, each with defined risk multipliers, severity classifications, and automated remediation workflows:

| # | Threat Category Code | Description | Default Severity | Risk Score Multiplier | Automated Action |
|---|---|---|---|---|---|
| 1 | `UNAUTHORIZED_INVOCATION` | Invocation attempted without a valid JWT token, with an expired signature, or from an unauthorized client network. | **CRITICAL** | 1.0 (Base 90–100) | Immediate Block (401/403) + Alert Dispatch |
| 2 | `PRIVILEGE_ESCALATION` | Authenticated principal attempting to invoke administrative or elevated endpoints outside assigned role scopes. | **CRITICAL** | 0.95 (Base 85–95) | Immediate Deny + Permission Invalidation Check |
| 3 | `EXCESSIVE_PERMISSIONS` | Execution context requesting or asserting privileges beyond minimal required function scope (Violating Principle of Least Privilege). | **HIGH** | 0.80 (Base 70–80) | Policy Warning or Deny based on enforcement mode |
| 4 | `SUSPICIOUS_FREQUENCY` | Request rate exceeding baseline threshold (>120 RPM or >35 RPS burst) from a single IP, user, or client fingerprint. | **HIGH** | 0.85 (Base 75–85) | Rate Limit (429) + Temporary Quota Penalty |
| 5 | `REPEATED_AUTH_FAILURES` | More than 5 consecutive authentication or MFA failures within a 5-minute sliding window. | **HIGH** | 0.90 (Base 80–90) | Account Lockout / IP Quarantine Alert |
| 6 | `MALFORMED_PAYLOAD` | Injection signatures detected in JSON payload body or query params (SQLi, XSS, CMDi, Path Traversal, prototype pollution). | **HIGH** | 0.85 (Base 75–85) | Payload Sanitization Reject (400/422) + Incident Log |
| 7 | `POLICY_VIOLATION` | Invocations outside authorized execution windows (e.g., restricted operational hours) or violating concurrency constraints. | **MEDIUM** | 0.60 (Base 50–65) | Policy Enforcement Deny (403) |
| 8 | `UNUSUAL_ACCESS_PATTERN` | Markov state machine deviation: sequence transition probability $P(S_t \mid S_{t-1}) = 0$ according to historical workflow models. | **HIGH** | 0.75 (Base 65–80) | Workflow Halt or Strict Audit Flagging |
| 9 | `DISABLED_FUNCTION_ACCESS`| Invocation request targeted at a serverless function whose lifecycle status is `INACTIVE`, `DEPRECATED`, or `QUARANTINED`. | **MEDIUM** | 0.65 (Base 55–70) | Reject (404/410/403) + Operational Alert |
| 10| `REPEATED_DENIED_OPS` | Principal or IP address accumulating $\ge 5$ blocked requests within a 120-second rolling window. | **CRITICAL** | 0.90 (Base 85–95) | IP Deny-list escalation + Security Incident Creation |

---

## 3. Mathematical Foundations & Risk Scoring Algorithm

The threat engine computes a composite risk score $R \in [0, 100]$ for each request by combining base vulnerability scores, contextual modifiers, and sliding window velocity penalties:

$$R = \min\left(100, \, \max_{k \in \mathcal{A}} \Big( B_k \times W_{\text{env}} \Big) + \sum_{j \in \mathcal{A}} \Delta_j + \delta_{\text{velocity}}\right)$$

Where:
- $\mathcal{A}$: Set of triggered threat alerts and rule anomalies for the invocation.
- $B_k$: Base severity score for threat rule $k$ ($B_{\text{CRITICAL}} \in [85, 100]$, $B_{\text{HIGH}} \in [70, 84]$, $B_{\text{MEDIUM}} \in [45, 69]$, $B_{\text{LOW}} \in [10, 44]$).
- $W_{\text{env}}$: Environmental criticality factor ($W_{\text{prod}} = 1.2$, $W_{\text{staging}} = 1.0$, $W_{\text{dev}} = 0.8$).
- $\Delta_j$: Additive penalty for secondary concurrent infractions (e.g., unapproved client runtime combined with elevated endpoint access).
- $\delta_{\text{velocity}}$: Dynamic velocity adjustment based on client denial count $D_{120}$ in the past 120 seconds:
  $$\delta_{\text{velocity}} = \min(25, \, 5 \times D_{120})$$

### Risk Classification Thresholds
- **$0 \le R < 30$ (LOW / CLEAN):** Request allowed to execute without restriction.
- **$30 \le R < 60$ (MEDIUM / CAUTION):** Request allowed with detailed audit tagging and sampling increase.
- **$60 \le R < 80$ (HIGH / RESTRICTED):** Request blocked if policy mode is `ENFORCING`; allowed with critical alert if `PERMISSIVE`.
- **$80 \le R \le 100$ (CRITICAL / SEVERE):** Immediate fail-closed rejection, automatic incident generation, and real-time SSE broadcast.

---

## 4. Sliding-Window Rate Limiting & Velocity Analysis

The threat detection engine implements an in-memory and database-backed sliding-window rate tracking algorithm:
1. Every client identifier (hashed IP address + authenticated user ID) maintains a rolling window of request timestamps.
2. Timestamps older than $t - \Delta T$ (where $\Delta T = 60\text{ seconds}$) are evicted.
3. If $|T_{\text{window}}| > \text{Threshold}_{\text{function}}$, a `SUSPICIOUS_FREQUENCY` threat is triggered.
4. Separate sliding windows track failed authentication attempts ($5\text{ attempts per } 300\text{ seconds}$) and denied invocations ($5\text{ denials per } 120\text{ seconds}$).

---

## 5. Markov Chain Sequence Anomaly Detection

To detect advanced persistent threats (APTs) and out-of-band invocation sequences (such as jumping straight to a high-value database operation without completing authentication or authorization steps), the engine maintains a state transition probability matrix:

$$T = \begin{pmatrix}
P(S_1 \to S_1) & P(S_1 \to S_2) & \dots & P(S_1 \to S_n) \\
P(S_2 \to S_1) & P(S_2 \to S_2) & \dots & P(S_2 \to S_n) \\
\vdots & \vdots & \ddots & \vdots \\
P(S_n \to S_1) & P(S_n \to S_2) & \dots & P(S_n \to S_n)
\end{pmatrix}$$

- Allowed transitions are initialized from known, verified workflow patterns (e.g., `auth/login` $\to$ `auth/mfa/verify` $\to$ `getDashboardMetrics` $\to$ `fetchAuditLogs`).
- An illegal transition (where $P(S_t \mid S_{t-1}) = 0$) immediately flags an `UNUSUAL_ACCESS_PATTERN` threat event.
- System transitions can be toggled between `STRICT_ENFORCE` (block illegal transitions) and `LEARNING_AUDIT` (log anomaly and increment transition count).

---

## 6. Incident Association & Automated Escalation

When threat events meet escalation criteria:
1. **Deduplication**: If an open incident already exists for the same principal and threat category within the last 15 minutes, the new alert is appended to the existing incident's evidence bundle.
2. **Incident Creation**: If no open incident exists, a new `SECURITY_INCIDENT` record is provisioned with status `OPEN`, assigned a unique UUID, and scored with the maximum severity of its constituent alerts.
3. **Evidence Snapshot**: The complete request payload, HTTP headers (with credentials redacted), IP provenance, verification step timing, and rule metadata are serialized into immutable JSON evidence logs.
4. **SSE Event Emission**: An incident alert is pushed over `/api/realtime/stream` to all active security administrator dashboards.
