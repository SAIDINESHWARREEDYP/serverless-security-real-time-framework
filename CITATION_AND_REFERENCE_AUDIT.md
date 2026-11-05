# CITATION AND REFERENCE AUDIT

**Project Title:** Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications  
**Citation Style:** IEEE Numbered Style  
**Verification Standard:** Strict Verification Against Official Published DOIs and RFC Specifications  

---

## 1. Verified Bibliography Entries

[1] C. Shin, B. Kim, and S. Lee, "BAMBDA: A Real-Time Verification Framework for Serverless Computing," *IEEE Access*, vol. 13, pp. 90896–90911, 2025, doi: 10.1109/ACCESS.2025.3572729.

[2] D. M'Raihi, S. Machani, M. Pei, and J. Rydell, "TOTP: Time-Based One-Time Password Algorithm," RFC 6238, Internet Engineering Task Force (IETF), May 2011, doi: 10.17487/RFC6238.

[3] M. Jones, J. Bradley, and N. Sakimura, "JSON Web Token (JWT)," RFC 7519, Internet Engineering Task Force (IETF), May 2015, doi: 10.17487/RFC7519.

[4] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, "Zero Trust Architecture," NIST Special Publication 800-207, National Institute of Standards and Technology, Gaithersburg, MD, Aug. 2020, doi: 10.6028/NIST.SP.800-207.

[5] B. Kaliski, "PKCS #5: Password-Based Cryptography Specification Version 2.0," RFC 2898 / RFC 8018, Internet Engineering Task Force (IETF), Sep. 2000, doi: 10.17487/RFC2898.

[6] OWASP Foundation, "OWASP Serverless Top 10," Open Web Application Security Project, 2021. [Online]. Available: https://owasp.org/www-project-serverless-top-10/

[7] Cloudflare, Inc., "Cloudflare Workers Documentation: Edge Compute and Runtime APIs," 2024. [Online]. Available: https://developers.cloudflare.com/workers/

[8] Cloudflare, Inc., "Cloudflare D1: Serverless Relational Database Documentation," 2024. [Online]. Available: https://developers.cloudflare.com/d1/

[9] E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3," RFC 8446, Internet Engineering Task Force (IETF), Aug. 2018, doi: 10.17487/RFC8446.

[10] D. Eastlake and P. Jones, "US Secure Hash Algorithm 1 (SHA1)," RFC 3174, Internet Engineering Task Force (IETF), Sep. 2001, doi: 10.17487/RFC3174.

[11] National Institute of Standards and Technology (NIST), "Secure Hash Standard (SHS)," FIPS PUB 180-4, Information Technology Laboratory, Gaithersburg, MD, Aug. 2015, doi: 10.6028/NIST.FIPS.180-4.

---

## 2. In-Text Citation Audit Matrix

| In-Text Citation Marker | Topic / Concept Referenced | Supporting Source in Code / System | Bibliography Entry | Validation Status |
|---|---|---|---|---|
| **[1]** | Runtime verification in serverless computing, log analysis overhead | Baseline research comparison, sequence tracking concepts | Shin et al., *IEEE Access*, 2025 | **VERIFIED** (Corrected page numbers: 90896–90911; verified DOI) |
| **[2]** | RFC 6238 TOTP time-step generation, HMAC-SHA1 counter, drift window | `server/utils/crypto.ts` (`computeTotp`, `verifyTotp`), `src/worker.ts` | RFC 6238 (IETF) | **VERIFIED** (Standard 30s step, ±1 tolerance, replay prevention implemented) |
| **[3]** | Cryptographic JWT claims structure, HMAC-SHA256 signing, expiration | `server/utils/crypto.ts` (`signJwt`, `verifyJwt`), `src/worker.ts` | RFC 7519 (IETF) | **VERIFIED** (Validates iss, aud, exp, nbf, sub, jti) |
| **[4]** | Zero Trust Architecture, continuous identity verification, assume breach | System gateway design, fail-closed enforcement, step arbitration | NIST SP 800-207 | **VERIFIED** (Never trust, always verify paradigm applied at each step) |
| **[5]** | PBKDF2 password derivation, salt generation, 100,000 iterations | `server/utils/crypto.ts` (`hashPassword`, `verifyPassword`), `src/worker.ts` | RFC 2898 / RFC 8018 | **VERIFIED** (PBKDF2-HMAC-SHA512 with 16-byte random salt) |
| **[6]** | Serverless threat vectors (IMDS SSRF, Command Injection, Insecure Deserialization) | `server/services/verification.service.ts` (`scanThreatVectors`) | OWASP Serverless Top 10 | **VERIFIED** (6 core threat categories implemented and tested) |
| **[7]** | Cloudflare Workers edge compute model, Web Crypto API | `src/worker.ts`, `wrangler.jsonc` | Cloudflare Workers Docs | **VERIFIED** (Web Crypto subtle API used without Node polyfills on edge) |
| **[8]** | Cloudflare D1 serverless SQL database, WAL mode, prepared statements | `src/worker.ts`, `migrations/` | Cloudflare D1 Docs | **VERIFIED** (D1 prepared statement contract faithfully implemented) |
| **[9]** | Secure channel transmission, TLS 1.3 standard | Transport protocol for HTTPS endpoints and SSE streams | RFC 8446 (IETF) | **VERIFIED** (Standard deployment transport) |
| **[10]** | SHA-1 hashing used in RFC 6238 TOTP algorithm | `server/utils/crypto.ts`, `src/worker.ts` | RFC 3174 (IETF) | **VERIFIED** (RFC 6238 standard HMAC-SHA1 computation) |
| **[11]** | SHA-256 cryptographic hash chaining for audit integrity | `server/repositories/audit.repository.ts` | FIPS PUB 180-4 (NIST) | **VERIFIED** (Cryptographic hash chaining verified across 100 entries) |

---

## 3. Discrepancy Corrections

1. **Base Paper Page Range:** Previously recorded as `35727–35745` in legacy notes. **Corrected** to canonical IEEE Access pagination: `vol. 13, pp. 90896–90911, 2025`.
2. **Unused References:** All external citations without directly matching source code or architectural components have been pruned.
3. **Attribution Authenticity:** Every cited RFC and standard is tied directly to the relevant function in `server/utils/crypto.ts` and `src/worker.ts`.
