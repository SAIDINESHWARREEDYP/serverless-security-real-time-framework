# Audit Logging & Incident Management Architecture

## 1. Executive Summary & Purpose

The Audit Logging and Incident Management subsystems provide the tamper-evident provenance and forensic lifecycle capabilities required for enterprise serverless compliance and real-time security operations. Every invocation decision, policy change, administrative operation, and authentication attempt is recorded in a cryptographically linked SHA-256 audit ledger. High-severity threats automatically generate tracked incidents with full lifecycle state machines (OPEN $\to$ INVESTIGATING $\to$ MITIGATED $\to$ RESOLVED $\to$ CLOSED).

---

## 2. Cryptographic Tamper-Evident Ledger Design

To satisfy non-repudiation and prevent audit log tampering by unauthorized administrators or compromised database operators, audit entries are chained together using a sequential Merkle-like SHA-256 hash pointer mechanism:

### 2.1 Hash Chain Formula

For every audit record $k \ge 1$:

$$H_k = \text{HMAC-SHA256}\Big( K_{\text{audit}}, \, H_{k-1} \,\|\, T_k \,\|\, U_k \,\|\, A_k \,\|\, R_k \,\|\, D_k \,\|\, S_k \Big)$$

Where:
- $H_k$: Cryptographic entry hash for record $k$.
- $H_{k-1}$: Previous entry hash (genesis block has $H_0 = \text{"0000000000000000000000000000000000000000000000000000000000000000"}$).
- $K_{\text{audit}}$: Secret ledger signing key maintained in secure environment configurations.
- $T_k$: ISO-8601 UTC timestamp of the event.
- $U_k$: Authenticated user ID or system service principal.
- $A_k$: Action name or serverless function invoked.
- $R_k$: Target resource or endpoint URI.
- $D_k$: Execution decision (`ALLOW`, `DENY`, `FLAGGED`, `ERROR`).
- $S_k$: Composite risk score and verification step metrics.

### 2.2 Tamper Verification Algorithm
The system provides an automated verification routine that traverses the audit log chronologically:
1. Fetch records ordered by `timestamp ASC, id ASC`.
2. Compute expected hash $\hat{H}_k = \text{HMAC-SHA256}(K_{\text{audit}}, H_{k-1} \,\|\, \text{fields}_k)$.
3. Compare $\hat{H}_k \stackrel{?}{=} H_k$.
4. If a mismatch is detected, the verification stops and flags an `INTEGRITY_BREACH` alert specifying the exact record ID where tampering occurred.

---

## 3. Audit Schema & Field Specification

Each record in the `audit_logs` table conforms to the following strict schema:

```sql
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    decision TEXT NOT NULL, -- 'ALLOW', 'DENY', 'FLAGGED', 'CHALLENGE'
    risk_score INTEGER NOT NULL,
    threat_category TEXT,
    execution_time_ms REAL NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
```

### 3.1 Field Level Sanitization & Privacy
- **Redaction of Sensitive Keys**: Headers such as `Authorization`, `Cookie`, `X-MFA-Code`, and private payload fields (`password`, `secret`, `ssn`) are sanitized before serialization into `metadata_json`.
- **IP Provenance**: Client IP addresses are stored for forensic geo-location and CIDR analysis.

---

## 4. Security Incident Lifecycle & Workflow

The Incident Management Engine tracks threats from initial detection through forensic review and final resolution.

```
       [Threat Detected]
              │
              ▼
         ┌─────────┐
         │  OPEN   │◄───────────────────────┐
         └────┬────┘                        │
              │ Assign Analyst              │ Reopen if
              ▼                             │ recurring
       ┌──────────────┐                     │
       │INVESTIGATING │                     │
       └──────┬───────┘                     │
              │ Apply Mitigation            │
              ▼                             │
        ┌───────────┐                       │
        │ MITIGATED │                       │
        └─────┬─────┘                       │
              │ Root Cause Resolved         │
              ▼                             │
        ┌───────────┐                       │
        │ RESOLVED  │───────────────────────┘
        └─────┬─────┘
              │ Formal Post-Mortem Sign-off
              ▼
         ┌────────┐
         │ CLOSED │
         └────────┘
```

### 4.1 Incident States & Transitions

1. **OPEN**: Incident created automatically by threat detection engine (Risk Score $\ge 75$ or Critical Category). Unassigned or assigned to triage queue.
2. **INVESTIGATING**: Security analyst actively reviewing forensic logs, payload traces, and invocation step breakdowns.
3. **MITIGATED**: Temporary countermeasures applied (e.g., principal rate-limited, API token revoked, IP address placed on temporary deny-list).
4. **RESOLVED**: Permanent fix deployed (e.g., IAM role permissions restricted, vulnerable function patched, firewall rule updated).
5. **CLOSED**: Auditor or Administrator review completed; post-incident review logged into tamper-evident ledger.

### 4.2 Incident Database Schema

```sql
CREATE TABLE IF NOT EXISTS security_incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    threat_category TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    status TEXT NOT NULL,   -- 'OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED', 'CLOSED'
    assigned_to TEXT,
    affected_resource TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    timeline_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT
);
```

---

## 5. Security Analyst Operations & Actions

Security personnel interacting with the Incident Management UI can execute the following real backend actions:
- **Change Status**: Advance incident state with mandatory reason logging.
- **Assign Investigator**: Assign to any user holding `SECURITY_ADMIN` or `SECURITY_ANALYST` role.
- **Append Forensic Note**: Add analyst notes with timestamps to `timeline_json`.
- **Execute Remediation Trigger**: One-click actions to revoke the offender's active JWT session or quarantine the targeted serverless function.
- **Export Forensic Package**: Generate a cryptographically signed JSON/CSV export for regulatory compliance and audit defense.
