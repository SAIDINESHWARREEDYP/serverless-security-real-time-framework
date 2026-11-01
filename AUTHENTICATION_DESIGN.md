# Authentication & Session Management Architecture Design

**Project**: Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications  
**Module**: Cryptographic Authentication, Token Engine & Multi-Factor Verification  
**Standard**: NIST SP 800-63B (Digital Identity Guidelines), RFC 7519 (JWT), RFC 6238 (TOTP)

---

## 1. Architectural Overview

The authentication engine operates on a zero-trust model where no caller is implicitly trusted based on network proximity or ambient identity. Authentication establishes identity through cryptographic proof before any request enters the invocation verification pipeline.

```
Caller (Client / Edge Device)
       │
       ▼
[ Rate Limiting & Brute-Force Shield ] (Max 5 attempts / 300s window)
       │
       ▼
[ Credential Verification ] ──▶ PBKDF2 (100,000 iterations, SHA-512, unique salt)
       │
       ▼
[ Account Clearance Check ] ──▶ Status must be 'APPROVED'
       │
       ▼
[ Multi-Factor Verification ] ──▶ RFC 6238 TOTP (Time-based One-Time Password)
       │
       ▼
[ Cryptographic Token Generation ] ──▶ HMAC-SHA256 JWT + D1 Atomic Session Record
       │
       ▼
Caller Receives Session Token & Verification Claims
```

---

## 2. Password Hashing Specification

- **Algorithm**: PBKDF2 (Password-Based Key Derivation Function 2)
- **Hash Function**: HMAC-SHA-512
- **Iteration Count**: 100,000 rounds
- **Salt Length**: 16 cryptographically secure random bytes (32 hexadecimal characters)
- **Derived Key Length**: 64 bytes (128 hexadecimal characters)
- **Storage Policy**: Zero plaintext password storage. Only `password_hash` and `password_salt` are stored in the Cloudflare D1 relational database.

---

## 3. Cryptographic Token (JWT) Specification

- **Signature Algorithm**: HMAC-SHA-256 (`HS256`)
- **Key Derivation**: High-entropy secret managed via environment variables (`JWT_SECRET`)
- **Token Claims**:
  - `sub`: Principal ID (`usr_*`)
  - `username`: Principal username
  - `role`: Canonical role string
  - `jti`: Unique session UUID
  - `iat`: Issue timestamp (Unix epoch seconds)
  - `exp`: Expiry timestamp (Unix epoch seconds, default 3,600s / 1 hour)
  - `iss`: `https://serverless-securityverification.ai.studio`
  - `aud`: `serverless-verification-mesh`

### Verification Invariants:
1. Tokens with `none` algorithm are rejected immediately.
2. Signatures are verified using cryptographic constant-time comparison to prevent timing side-channel attacks.
3. Expired tokens (`Date.now() / 1000 >= exp`) trigger HTTP 401 with `TOKEN_EXPIRED`.
4. Tampered claims invalidate signature comparison, returning HTTP 401 with `SIGNATURE_INVALID`.

---

## 4. Multi-Factor Authentication (MFA) Specification

- **Protocol**: RFC 6238 Time-based One-Time Password (TOTP)
- **Time Step ($T_0$)**: 30 seconds
- **HMAC Algorithm**: SHA-1 / Base32 Secret Key
- **Code Length**: 6 digits
- **Drift Tolerance Window**: $\pm 1$ step (90 seconds total validity window)
- **Secrets Management**: Secrets are stored encrypted in Cloudflare D1 and are **never** returned in API responses.
- **Fail-Closed Guarantees**: MFA cannot be bypassed using demo flags or default dummy parameters in production mode.

---

## 5. Session Lifecycle & Revocation Specification

1. **Session Issuance**: Upon successful credential & MFA validation, an atomic session row is written to the D1 `sessions` table with status `'active'`.
2. **Session Verification**: The `authenticateMiddleware` validates both the JWT cryptographic signature and checks that the session record in D1 has not been revoked (`status = 'active'`).
3. **Session Revocation**: An Administrator triggers `/api/auth/revoke-session`. The target session is atomically marked as `'revoked'` with timestamp, revoking administrator ID, and justification.
4. **Immediate Invalidation**: The revoked session's token is immediately rejected on subsequent requests, terminating access within $<1$ ms.
