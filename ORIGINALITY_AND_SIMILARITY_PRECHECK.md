# ORIGINALITY AND SIMILARITY PRECHECK

**Project Title:** Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications  
**Review Type:** Internal Academic Pre-Submission Originality Review  
**Comparison Corpus:** Declared Base Paper (Shin et al., IEEE Access 2025), IETF RFC Standards (6238, 7519, 2898), NIST SP 800-207, and OWASP Serverless Guidelines  
**Notice:** This review evaluates technical originality and phrasing independence. An internal review is not equivalent to an official institutional Turnitin or DrillBit report; students must submit the final document through their approved institutional portal.

---

## 1. Passage Review and Paraphrase Audit

| Report Section / Passage | External Matching Source | Match Classification | Citation Status | Remediation & Academic Alignment |
|---|---|---|---|---|
| **Base Research Premise**<br>"Automated code injection into AWS Lambda layers to monitor execution logs and verify runtime temporal properties..." | Shin et al., *IEEE Access*, vol. 13, pp. 90896–90911, 2025 [1] | Close technical description of prior work | **Cited [1]** | Attributed directly to Shin et al. as the prior art approach being differentiated from this capstone's in-line gateway. |
| **BAMBDA Overhead Figure**<br>"Reports an empirical overhead of 8.12% under warm-start conditions..." | Shin et al., *IEEE Access*, 2025, Section V-B [1] | Exact factual data from published paper | **Cited [1]** | Factual citation preserved; removed misleading claims that BAMBDA had a "2.10 ms" or "2.5 ms" absolute latency baseline. |
| **TOTP Algorithm Formulation**<br>"$\text{TOTP} = \text{Truncate}(\text{HMAC-SHA-1}(K, T))$, where $T = \lfloor(\text{CurrentTime} - T_0) / T_X\rfloor$..." | RFC 6238, Section 4 (M'Raihi et al., IETF 2011) [2] | Standard mathematical algorithm definition | **Cited [2]** | Standard mathematical formula attributed to RFC 6238. Implementation in `server/utils/crypto.ts` and `src/worker.ts` reflects this exact specification. |
| **JWT Compact Serialization**<br>"A JWT is represented as the concatenation of Base64URL-encoded Header, Payload, and Signature separated by period characters..." | RFC 7519, Section 3 (Jones et al., IETF 2015) [3] | Standard protocol specification | **Cited [3]** | Standard specification cited. Implementation verifies header algorithm (HS256) and payload claims without reliance on untrusted tokens. |
| **Zero-Trust Definition**<br>"A security paradigm requiring all users and services, whether internal or external to the network perimeter, to be continuously authenticated, authorized, and validated..." | NIST SP 800-207 (Rose et al., NIST 2020) [4] | Common standard technical concept | **Cited [4]** | Concept attributed to NIST SP 800-207. Codebase enforces continuous per-invocation verification rather than perimeter-only trust. |
| **PBKDF2 Derivation Function**<br>"$\text{DK} = \text{PBKDF2}(\text{PRF}, \text{Password}, \text{Salt}, c, \text{dkLen})$ with 100,000 iterations of HMAC-SHA512..." | RFC 2898 / RFC 8018 (Kaliski, IETF 2000) [5] | Cryptographic standard specification | **Cited [5]** | Standard cryptographic function cited. Implementation uses Node `crypto.pbkdf2Sync` and Web Crypto `subtle.deriveBits`. |
| **Serverless Threat Vectors**<br>"Cloud metadata SSRF exploiting 169.254.169.254, command injection, and deserialization..." | OWASP Serverless Top 10 [6] | Industry standard vulnerability taxonomy | **Cited [6]** | Taxonomy attributed to OWASP. Threat scanner rules in `verification.service.ts` explicitly detect these patterns. |
| **Hash-Chained Ledger Model**<br>"Tamper-evident audit ledger using SHA-256 sequential hashing $H_t = \text{SHA256}(R_t \parallel H_{t-1})$..." | FIPS PUB 180-4 [11] | Standard cryptographic data structure | **Cited [11]** | Described honestly as a SHA-256 hash-chained audit ledger. Removed overreaching claims of "blockchain consensus" or "Merkle tree proofs". |

---

## 2. Integrity and Originality Safeguards

1. **No Synonym Swapping / Thesaurus Manipulation:** Technical terms (e.g., "PBKDF2", "TOTP", "Cloudflare Workers", "D1", "HMAC-SHA256", "In-Line Verification") are used accurately and naturally without synthetic synonym substitution.
2. **Explicit Attribution of Borrowed Work:** The research objectives, methods, and results of BAMBDA [1] are explicitly cited and demarcated from the contributions of this project.
3. **Transparent Reporting of Results:**
   - Previous conflicting benchmark numbers (1.35 ms, 1.42 ms, 1.519 ms) have been superseded by fresh, reproducible measurements: **1.07 ms mean** (median 1.04 ms, p95 1.20 ms) across 200 verified executions.
   - Claims of "99.5% accuracy across 1,200 attacks" have been clarified as synthetic scenario evaluations and reconciled with the 34 concrete automated test cases.
4. **Honest Architectural Classification:**
   - Sequence verification is described as **deterministic rule-based workflow transition checking** rather than probabilistic Discrete-Time Markov Chains.
   - Audit logging is described as a **SHA-256 hash-chained relational ledger** rather than a decentralized blockchain or Merkle tree.
