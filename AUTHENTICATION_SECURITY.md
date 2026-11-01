# Authentication Security & Session Governance

## 1. Zero-Trust Identity Model
Under the Zero-Trust Architecture (NIST SP 800-207), no user or workload is trusted implicitly. Every request must present cryptographically verifiable proof of authentication and session validity.

---

## 2. Password Security & Hashing
- **Algorithm**: Password-Based Key Derivation Function 2 (PBKDF2)
- **Hash Primitive**: HMAC-SHA-512
- **Iteration Rounds**: 100,000 iterations
- **Cryptographic Salt**: 16 cryptographically secure pseudo-random bytes (32 hex characters) generated per user via `crypto.randomBytes(16)`
- **Derived Key Length**: 64 bytes (128 hex characters)
- **Zero Plaintext Storage**: Plaintext passwords are never stored in database tables or logs. Only `password_hash` and `password_salt` are stored.
- **Verification**: Evaluated using constant-time `crypto.timingSafeEqual` to eliminate timing side-channel attacks.

---

## 3. Cryptographic Token Generation (RFC 7519 JWT)
- **Algorithm**: HMAC-SHA-256 (`HS256`)
- **Secret Management**: High-entropy 256-bit secret loaded from environment variables (`JWT_SECRET`).
- **Standard Claims Enforced**:
  - `sub`: Principal user ID (`usr_*`)
  - `username`: Principal handle (e.g. `secops_admin`)
  - `role`: Canonical RBAC role (e.g. `Super Administrator`)
  - `jti`: Unique session identifier (`jti_*`)
  - `iss`: `https://auth.serverless-security.local`
  - `aud`: `serverless-security-framework`
  - `iat`: Issue timestamp (Unix epoch seconds)
  - `nbf`: Not before timestamp (Unix epoch seconds)
  - `exp`: Expiry timestamp (default: 3,600s / 1 hour)
- **Token Verification**: Validates signature bytes, expiration (`now >= exp`), not-before (`now < nbf`), issuer, and audience before claims are parsed.

---

## 4. Multi-Factor Authentication (MFA)
- **Standard**: RFC 6238 Time-based One-Time Password (TOTP).
- **Time Step ($T_0$)**: 30 seconds.
- **Hashing**: HMAC-SHA1 over 8-byte big-endian time-step buffer.
- **Base32 Secret**: 160-bit cryptographically secure Base32 secret stored per user. Secrets are strictly stripped from all ordinary user API responses.
- **Window Tolerance**: $\pm 2$ time steps ($60\text{ seconds}$ drift leeway) to accommodate client-server NTP clock skew without weakening entropy.
- **Carrier SMS Fallback**: Dispatches one-time numeric passcode to registered phone (`+1 (555) •••-4829`).
- **Backup Recovery Codes**: Pre-generated 8-character single-use recovery codes (`XXXX-XXXX`). Codes are consumed upon use to prevent replay.

---

## 5. Brute-Force Safeguards & Account Lockout
- **Rate-Limiter Window**: 60-second sliding evaluation window.
- **Failure Threshold**: 5 consecutive failed authentication attempts on an IP or account identifier.
- **Lockout Duration**: 300 seconds ($5\text{ minutes}$) automated lockout. Returns HTTP 429 Too Many Requests with `retryAfterSeconds`.
- **Reset on Success**: Successful authentication immediately clears the failed attempt counter.

---

## 6. Real-Time Database Session Revocation
- **Registry**: Cloudflare D1 `active_sessions` table.
- **Revocation API**: `POST /api/v1/auth/revoke-session` (Admin only).
- **Revocation Propagation**: Atomically sets `status = 'revoked'`, `revoked_at = datetime('now')`, `revoked_by`, and `revocation_reason`.
- **Edge Invalidation**: On every invocation, Step 4 of the verification pipeline queries D1 session state. A revoked session is immediately terminated across all global edge nodes with HTTP 401 `AUTH_TOKEN_REVOKED`.
