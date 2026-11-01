# PHASE 13 — Production Deployment Guide

## 1. Prerequisites
- **Node.js**: v18.0.0 or later (Node.js 20.x recommended)
- **Package Manager**: npm or bun
- **Cloud Platform**: Cloudflare Workers / Pages or containerized Node.js (Docker, Google Cloud Run)

---

## 2. Environment Configuration

Create a `.env` file in the project root based on `.env.example`:

```bash
PORT=3000
NODE_ENV=production
JWT_SECRET=production_enterprise_master_jwt_secret_2026_change_in_prod
JWT_ISSUER=https://auth.serverless-security.local
JWT_AUDIENCE=serverless-security-framework
MAX_PAYLOAD_BYTES=1048576
MFA_WINDOW=2
MFA_STEP_SECONDS=30
```

---

## 3. Local & Containerized Build & Run

```bash
# 1. Install dependencies
npm install

# 2. Compile application (frontend bundle + TypeScript backend check)
npm run build

# 3. Run production server
npm start
```

---

## 4. Cloudflare Workers & D1 Deployment

```bash
# 1. Login to Cloudflare CLI
npx wrangler login

# 2. Provision Cloudflare D1 Database
npx wrangler d1 create serverless-security-db

# 3. Apply SQL migrations
npx wrangler d1 execute serverless-security-db --file=./migrations/0001_initial_schema.sql

# 4. Deploy Serverless Worker
npx wrangler deploy
```

---

## 5. Production Health Verification

After deploying, verify the health status:

```bash
curl -i https://<your-domain>/api/system/health
```

Expected response:
```json
{
  "status": "HEALTHY",
  "d1_database": "CONNECTED",
  "auth_service": "OPERATIONAL",
  "verification_engine": "ACTIVE",
  "fail_closed_mode": "ACTIVE"
}
```
