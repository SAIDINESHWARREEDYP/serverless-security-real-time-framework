# FUNCTIONAL DEFECT & BUG REPORT

**Project:** Serverless Security Verification Framework  
**Scope:** Functional bugs, UI discrepancies, logic flaws, state management issues, and edge-case exceptions.  
**Audit Date:** October 30, 2026  

---

## Bug Index

1. [BUG-01] Critical: Volatile In-Memory Database Resetting on Server Reboot
2. [BUG-02] High: Incomplete Cloudflare Worker Route Handlers
3. [BUG-03] High: Plaintext Password Exposure in Client-Side State
4. [BUG-04] Medium: Polling Memory Leak in Overview Poller
5. [BUG-05] Medium: Inconsistent Latency Fallback Calculation in Frontend Visualizers
6. [BUG-06] Medium: Lack of Input Sanitization on Identity Username Creation
7. [BUG-07] Low: CSV Export Quote Escaping Edge-Case on Raw JSON Strings
8. [BUG-08] Low: Mobile Layout Overflow on Wide Tabular Visualizers

---

## Detailed Bug Reports

### [BUG-01] Volatile In-Memory Database Resetting on Server Reboot
- **File Path:** `/server/db.ts`
- **Function / Component:** `SecurityDatabase` class constructor and internal storage
- **Exact Problem:** All user records, dynamic registrations, active sessions, and audit logs are stored in memory (`this.users = []`, `this.logs = []`). Whenever the Node.js development server reloads or restarts, all runtime state is lost and restored to hardcoded seed data.
- **Severity:** **Critical**
- **Functional Impact:** Dynamic identities registered during runtime disappear; newly revoked sessions become valid again after server restart.
- **Recommended Correction:**
  Implement persistent storage using a local SQLite file (e.g. SQLite database file in `/server/data.db` using `better-sqlite3` or Node fs persistence) matching the D1 migration schema.
- **How to Verify:**
  Register a user via `/api/register`, trigger a server restart, and verify the user still appears in `/api/system/overview`.

---

### [BUG-02] Incomplete Cloudflare Worker Route Handlers
- **File Path:** `/src/worker.ts`
- **Function / Component:** `export default { async fetch(...) }`
- **Exact Problem:** `src/worker.ts` only provides endpoints for `/api/health`, `/api/auth/revoke-session`, and `/api/:route`. It lacks implementations for `/api/login`, `/api/register`, `/api/auth/status`, `/api/auth/mfa/send-sms`, `/api/auth/mfa/verify`, and `/api/system/*`.
- **Severity:** **High**
- **Functional Impact:** Deploying the worker to Cloudflare Workers causes the frontend to break completely upon attempting login or overview sync.
- **Recommended Correction:**
  Consolidate backend routing logic into shared or edge-compatible modules that work identically under Node.js and Cloudflare Workers.
- **How to Verify:**
  Simulate worker requests to `/api/login` and `/api/system/overview` and ensure valid JSON responses instead of 404 Not Found.

---

### [BUG-03] Plaintext Password Exposure in Client-Side State
- **File Path:** `/src/App.tsx` and `/src/components/UserDatabaseModal.tsx`
- **Function / Component:** `fetchOverview()` and `users` state
- **Exact Problem:** The backend `/api/system/overview` endpoint returns the full user object including `password_hash: "ZeroTrust_2026"`. The frontend stores this in React state and passes it to components.
- **Severity:** **High**
- **Functional Impact:** Any user inspecting React state (e.g. via browser devtools) can view the plaintext passwords of all other registered accounts.
- **Recommended Correction:**
  Strip `password_hash` from the backend API response before sending it to the client.
- **How to Verify:**
  Open browser developer console, execute `fetch('/api/system/overview').then(r=>r.json()).then(d=>console.log(d.users[0]))`, and verify that `password_hash` is undefined.

---

### [BUG-04] Polling Race Condition & Interval Accumulation
- **File Path:** `/src/App.tsx`
- **Function / Component:** `useEffect` around lines ~329–340
- **Exact Problem:** `fetchOverview` is invoked every 4,000ms using `setInterval`. If a request experiences network latency or server pause, multiple unresolved requests can queue up, resulting in state flickering or race conditions when responses arrive out of order.
- **Severity:** **Medium**
- **Functional Impact:** Unnecessary network overhead and potential state jitter on slow connections.
- **Recommended Correction:**
  Use recursive `setTimeout` pattern inside `useEffect` so the next poll is only scheduled 4 seconds after the previous request successfully completes.
- **How to Verify:**
  Throttle network to "Slow 3G" in browser devtools and observe request flow in Network tab; verify that concurrent requests do not pile up.

---

### [BUG-05] Inconsistent Latency Fallback Calculation in Frontend Visualizers
- **File Path:** `/src/components/SystemHealthDashboard.tsx`
- **Function / Component:** `latencyTrendData` useMemo calculation
- **Exact Problem:** When older audit logs lack `verification_latency_ms`, the component generates a fallback value: `Number((0.28 + (log.calculated_risk % 20) * 0.02).toFixed(3))`. This can produce slightly artificial latency numbers for historical events.
- **Severity:** **Medium**
- **Functional Impact:** Minor metric skew on synthetic historical records.
- **Recommended Correction:**
  Ensure the backend database migration schema assigns a mandatory default `0.35` REAL value to `verification_latency_ms` on all inserts, eliminating the need for client-side heuristic fallbacks.
- **How to Verify:**
  Inspect the D1 database records directly and verify that every record in `audit_events` and `security_audit_logs` has an explicit non-null `verification_latency_ms`.

---

### [BUG-06] Lack of Input Sanitization on Identity Username Creation
- **File Path:** `/server.ts`
- **Function / Component:** `POST /api/system/users` and `POST /api/register`
- **Exact Problem:** Usernames are trimmed and converted to lowercase, but no regex validation enforces alphanumeric or length restrictions (e.g. rejecting `<script>` tags, emojis, or SQL special characters in usernames).
- **Severity:** **Medium**
- **Functional Impact:** Potential stored XSS risk if unsanitized usernames are rendered in unsafe DOM contexts.
- **Recommended Correction:**
  Validate usernames with strict regex: `^[a-zA-Z0-9_]{3,32}$`. Reject invalid usernames with HTTP 400.
- **How to Verify:**
  Submit `POST /api/register` with `{"username": "<script>alert(1)</script>"}`. Confirm server returns HTTP 400 Bad Request.

---

### [BUG-07] CSV Export Quote Escaping Edge-Case on Raw JSON Strings
- **File Path:** `/src/components/AuditLogStream.tsx` and `/src/components/SystemHealthDashboard.tsx`
- **Function / Component:** `handleDownloadCSV` and `handleExportRiskCSV`
- **Exact Problem:** When log `reason` strings contain complex nested quotes or unescaped line breaks, the simple `replace(/"/g, '""')` escaping can occasionally produce multi-line rows in older spreadsheet viewers (e.g. Excel 2013).
- **Severity:** **Low**
- **Functional Impact:** Minor formatting misalignment when opening CSV in legacy spreadsheet software.
- **Recommended Correction:**
  Sanitize internal line breaks (`\r\n` -> ` `) inside cells prior to wrapping in quotes.
- **How to Verify:**
  Generate a log with newlines in the reason string, export CSV, and open in Excel or LibreOffice Calc. Verify each record occupies exactly one row.

---

### [BUG-08] Mobile Layout Horizontal Scroll on Complex Data Tables
- **File Path:** `/src/components/AuditLogStream.tsx` and `/src/components/UserDatabaseModal.tsx`
- **Function / Component:** Responsive table wrappers
- **Exact Problem:** On viewport widths $< 400\text{px}$, wide 7-column tables require extensive horizontal scrolling without visual scrollbar indicators on iOS Safari.
- **Severity:** **Low**
- **Functional Impact:** Degraded user experience on small mobile screens.
- **Recommended Correction:**
  Provide responsive card view alternatives for mobile viewports using `@media (max-width: 640px)`.
- **How to Verify:**
  Emulate iPhone SE ($375\text{px}$ width) in browser devtools and verify table accessibility.
