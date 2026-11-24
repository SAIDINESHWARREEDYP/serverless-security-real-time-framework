# Production & Cloudflare Edge Deployment Guide

## 1. Prerequisites
- **Node.js**: v20.0.0 or later
- **Package Manager**: `npm`
- **Cloudflare CLI** (for Workers + D1 deployment): `wrangler` (`npx wrangler --version`)

> **Verification Scope Note**: Offline sandbox environments validate the Worker TypeScript bundle (`esbuild`) and local SQLite-backed D1 emulation (`D1Database.prepare/bind/batch`), not live remote Cloudflare infrastructure. Execute Sections 4–6 against your Cloudflare account to verify remote Worker + D1 persistence and concurrency.

---

## 2. Environment & Anchor Key Configuration

Copy `.env.example` to `.env` for Node/Express deployments:

```bash
PORT=3000
NODE_ENV=production
JWT_SECRET=<at_least_32_char_random_hex_secret>
AUDIT_ANCHOR_KEY=<at_least_32_char_dedicated_anchor_hmac_secret>
AUDIT_ANCHOR_KEY_ID=anchor-v1
AUDIT_ANCHOR_PREVIOUS_KEYS=""
```

For Cloudflare Workers (`wrangler`):

```bash
npx wrangler secret put JWT_SECRET
npx wrangler secret put AUDIT_ANCHOR_KEY
npx wrangler secret put INITIAL_ADMIN_PASSWORD
```

Never commit plaintext secrets or expose `JWT_SECRET` / `AUDIT_ANCHOR_KEY` to client bundles or logs.

---

## 3. Local & Containerized Build & Run

```bash
npm install
npm run build
npm start
```

---

## 4. Cloudflare Workers & Remote D1 Deployment Verification

Apply **all** D1 migrations in strict numerical order before serving traffic:

```bash
# 1. Authenticate & create remote D1 database
npx wrangler login
npx wrangler d1 create serverless-security-db

# 2. Apply migrations 0001 through 0004 cleanly to remote D1
npx wrangler d1 execute serverless-security-db --remote --file=./migrations/0001_initial_schema.sql
npx wrangler d1 execute serverless-security-db --remote --file=./migrations/0002_normalized_d1_schema.sql
npx wrangler d1 execute serverless-security-db --remote --file=./migrations/0003_secure_auth_and_persistence.sql
npx wrangler d1 execute serverless-security-db --remote --file=./migrations/0004_mfa_enrollment_status.sql

# 3. Verify applied schema migrations & tables on remote D1
npx wrangler d1 execute serverless-security-db --remote --command="SELECT version, applied_at FROM schema_migrations ORDER BY version ASC;"

# 4. Deploy Worker bundle
npx wrangler deploy
```

---

## 5. Legacy Audit Baseline & Key Rotation Procedures

### A. Inspect & Seal Archived Legacy History (Never Alters Historical Rows)
If an upgraded database contains historical rows created prior to full-ledger SHA-256 hash chaining:

```bash
# Dry-run inspection (reports suggested cutoff & broken rows without mutating DB)
npm run audit:baseline -- --inspect

# Seal archived legacy rows up to suggested cutoff & establish a verified modern epoch
npm run audit:baseline -- --apply --admin=secops_admin
```

Or via authenticated Administrator API:
- `POST /api/v1/audit/baseline-legacy` (body: `{ cutoffMaxId?, epochLabel?, reason? }`)

### B. Audit Chain Anchor Key Rotation
To rotate the HMAC signing key protecting `audit_chain_anchor`:
1. Configure `AUDIT_ANCHOR_PREVIOUS_KEYS="anchor-v1:<old_secret>"` if supplying an external secret so historical `audit_ledger_epochs` records continue verifying.
2. Call `POST /api/v1/audit/rotate-anchor-key` as an Administrator (`newKeyId`, optional `newSecret`).

---

## 6. Remote Post-Deployment Verification Checklist

Run against your deployed `https://<worker-subdomain>.workers.dev` URL:

1. **Health & D1 Connectivity**: `GET /api/system/health` -> HTTP `200`, `isConnected: true`.
2. **Remote Persistence & Audit Chain Integrity**:
   - Authenticate via `POST /api/login` + `POST /api/auth/mfa/verify`.
   - Trigger traffic via `POST /api/getDashboardMetrics`, then query `GET /api/v1/audit/verify-chain`.
   - Confirm `chainIntact: true` (or `VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY` if legacy epochs are sealed) and `anchorVerified: true`.
3. **Recovery-Code Concurrency on Remote D1**:
   - Trigger parallel `POST /api/auth/mfa/enroll-challenge` calls during enrollment and confirm identical recovery code set / single-use CAS consumption under parallel verify retries.
