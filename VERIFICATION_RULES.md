# Serverless Security Verification Rules & State Machine Specification

**Project**: Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications  
**Module**: Markov Transition Matrix & Verification Invariant Rules

---

## 1. Markov State Transition Machine

In a microservice or serverless cloud topology, benign operations follow predictable workflow state transitions (e.g., authentication must precede telemetry inspection; telemetry inspection precedes deployment; deployment precedes policy mutation).

Out-of-order or lateral movement jumps indicate credential stuffing, stolen token re-use, or privilege exploration.

### Permitted Function Transition Matrix

| Current State ($F_{t-1}$) | Allowed Successor State ($F_t$) | Transition Probability ($P$) | Enforcement Action on Breach |
| :--- | :--- | :---: | :--- |
| `login` | `getDashboardMetrics` | $1.00$ | Sequence Penalty $+40\%$ |
| `getDashboardMetrics` | `viewSecurityLogs` | $0.85$ | Sequence Penalty $+40\%$ |
| `getDashboardMetrics` | `viewAuditEvents` | $0.90$ | Sequence Penalty $+40\%$ |
| `viewSecurityLogs` | `deployWorkerCode` | $0.75$ | Sequence Penalty $+40\%$ |
| `viewSecurityLogs` | `rotateEncryptionKeys` | $0.60$ | Sequence Penalty $+40\%$ |
| `deployWorkerCode` | `updateSystemPolicy` | $0.80$ | Sequence Penalty $+40\%$ |
| `rotateEncryptionKeys` | `purgeColdStorageBackups` | $0.95$ | Sequence Penalty $+40\%$ |

---

## 2. Threat Detection Signatures & Indicators

The verification engine inspects payload buffers for specific adversarial signatures:

### 1. Cloud Metadata / IMDS SSRF
- **Indicators**: `169.254.169.254`, `metadata.google.internal`, `computemetadata/v1`, `latest/meta-data`, `0xa9.0xfe.0xa9.0xfe`, `2852039166`, `/var/run/secrets`
- **Penalty**: $+95$
- **Severity**: `CRITICAL`
- **Action**: Immediate HTTP 403, Security Alert created in D1.

### 2. OS Command Injection
- **Indicators**: `/bin/sh`, `/bin/bash`, `; rm -rf`, `| nc `, `` `id` ``, `$(whoami)`, `powershell -e`
- **Penalty**: $+90$
- **Severity**: `CRITICAL`
- **Action**: Execution killed, immediate HTTP 403.

### 3. Adversarial Prompt Injection
- **Indicators**: `ignore previous`, `disregard previous`, `you are now`, `dan mode`, `system prompt`, `reveal secret`
- **Penalty**: $+85$
- **Severity**: `HIGH`
- **Action**: Input dropped, anomaly incident opened.

### 4. High-Entropy Credential Exfiltration
- **Indicators**: AWS Access Key pattern (`AKIA[0-9A-Z]{16}`), OpenAI token (`sk-[a-zA-Z0-9]{20,}`), Google API Key (`AIzaSy...`), RSA private key headers
- **Penalty**: $+90$
- **Severity**: `CRITICAL`
- **Action**: Blocked from outbound egress.

### 5. SQL / NoSQL Injection
- **Indicators**: `' OR '1'='1`, `UNION SELECT`, `; DROP TABLE`, `{"$gt":`, `{"$where":`, `SLEEP(`, `BENCHMARK(`
- **Penalty**: $+80$
- **Severity**: `HIGH`
- **Action**: Query blocked, transaction rolled back.

---

## 3. Rate Limiting & Velocity Bounds

- **Evaluation Window**: Sliding 60 seconds
- **Baseline Threshold**: 10 requests / 60s
- **Penalty**: $+20$ risk score applied dynamically when request count exceeds threshold
- **Lockout Boundary**: 5 consecutive failed authentications triggers 300s account freeze
