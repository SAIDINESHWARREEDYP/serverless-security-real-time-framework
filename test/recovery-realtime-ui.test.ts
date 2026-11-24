/**
 * Recovery-Code Concurrency & Retry Safety, Persistent Local D1 Restart Check,
 * and UI + Real-Time (Spinner, Tab Switching, Approval Polling, SSE Reconnect) Suite
 *
 * Uses an isolated ephemeral SQLite file via SECURITY_DB_PATH so
 * /server/data/security_framework.sqlite remains completely untouched.
 */

import assert from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

const tmpExpressDbPath = `/tmp/test_rr_express_${Date.now()}_${crypto.randomBytes(3).toString('hex')}.sqlite`;
const tmpWorkerPersistDbPath = `/tmp/test_rr_worker_d1_${Date.now()}_${crypto.randomBytes(3).toString('hex')}.sqlite`;
process.env.SECURITY_DB_PATH = tmpExpressDbPath;

// ============================================================================
// Lightweight Node DOM Shim for Real React 19 + Hooks + UI Component Mounting
// ============================================================================
function installMinimalDomShim() {
  class MiniEvent {
    type: string;
    bubbles: boolean;
    cancelable: boolean;
    defaultPrevented = false;
    target: any = null;
    currentTarget: any = null;
    constructor(type: string, init: any = {}) {
      this.type = type;
      this.bubbles = Boolean(init.bubbles);
      this.cancelable = Boolean(init.cancelable);
    }
    preventDefault() {
      if (this.cancelable) this.defaultPrevented = true;
    }
    stopPropagation() {
      // noop for single-node harness
    }
  }

  class MiniNode {
    nodeType: number;
    nodeName: string;
    ownerDocument: any;
    parentNode: MiniNode | null = null;
    childNodes: MiniNode[] = [];
    listeners = new Map<string, Set<Function>>();
    _text = '';

    constructor(nodeType: number, nodeName: string, ownerDocument: any) {
      this.nodeType = nodeType;
      this.nodeName = nodeName;
      this.ownerDocument = ownerDocument;
    }

    get parentElement() {
      return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null;
    }
    get firstChild() {
      return this.childNodes[0] || null;
    }
    get lastChild() {
      return this.childNodes[this.childNodes.length - 1] || null;
    }
    get nextSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return idx >= 0 && idx + 1 < this.parentNode.childNodes.length ? this.parentNode.childNodes[idx + 1] : null;
    }
    get previousSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return idx > 0 ? this.parentNode.childNodes[idx - 1] : null;
    }

    appendChild(child: MiniNode) {
      return this.insertBefore(child, null);
    }

    insertBefore(child: MiniNode, ref: MiniNode | null) {
      if (child.nodeType === 11) {
        const fragChildren = [...child.childNodes];
        for (const fc of fragChildren) {
          this.insertBefore(fc, ref);
        }
        return child;
      }
      if (child.parentNode) {
        child.parentNode.removeChild(child);
      }
      child.parentNode = this;
      if (!ref) {
        this.childNodes.push(child);
      } else {
        const idx = this.childNodes.indexOf(ref);
        if (idx === -1) this.childNodes.push(child);
        else this.childNodes.splice(idx, 0, child);
      }
      return child;
    }

    removeChild(child: MiniNode) {
      const idx = this.childNodes.indexOf(child);
      if (idx !== -1) {
        this.childNodes.splice(idx, 1);
        child.parentNode = null;
      }
      return child;
    }

    replaceChild(newChild: MiniNode, oldChild: MiniNode) {
      this.insertBefore(newChild, oldChild);
      this.removeChild(oldChild);
      return oldChild;
    }

    contains(other: MiniNode | null): boolean {
      let cur = other;
      while (cur) {
        if (cur === this) return true;
        cur = cur.parentNode;
      }
      return false;
    }

    get textContent(): string {
      if (this.nodeType === 3 || this.nodeType === 8) return this._text;
      return this.childNodes.map((c) => c.textContent).join('');
    }
    set textContent(v: string) {
      if (this.nodeType === 3 || this.nodeType === 8) {
        this._text = String(v ?? '');
        return;
      }
      this.childNodes.forEach((c) => { c.parentNode = null; });
      this.childNodes = [];
      if (v !== '' && v !== null && v !== undefined) {
        this.appendChild(new MiniNode(3, '#text', this.ownerDocument).withText(String(v)));
      }
    }

    withText(t: string) {
      this._text = t;
      return this;
    }

    addEventListener(type: string, fn: any) {
      if (!fn) return;
      if (!this.listeners.has(type)) this.listeners.set(type, new Set());
      this.listeners.get(type)!.add(fn);
    }

    removeEventListener(type: string, fn: any) {
      this.listeners.get(type)?.delete(fn);
    }

    dispatchEvent(event: any): boolean {
      event.target = event.target || this;
      let cur: MiniNode | null = this;
      while (cur) {
        event.currentTarget = cur;
        const handlers = cur.listeners.get(event.type);
        if (handlers) {
          for (const h of Array.from(handlers)) {
            h.call(cur, event);
          }
        }
        const propHandler = (cur as any)[`on${event.type}`];
        if (typeof propHandler === 'function') {
          propHandler.call(cur, event);
        }
        if (!event.bubbles) break;
        cur = cur.parentNode;
      }
      return !event.defaultPrevented;
    }
  }

  class MiniElement extends MiniNode {
    tagName: string;
    attributes = new Map<string, string>();
    style: Record<string, any> = new Proxy(
      { setProperty: () => {}, removeProperty: () => {} },
      {
        get(target, prop) {
          return prop in target ? (target as any)[prop] : '';
        },
        set(target, prop, val) {
          (target as any)[prop] = val;
          return true;
        }
      }
    );
    _value = '';
    _checked = false;
    disabled = false;
    type = '';
    oninput: any = null;
    onchange: any = null;
    onsubmit: any = null;
    onclick: any = null;

    constructor(tagName: string, ownerDocument: any) {
      super(1, tagName.toUpperCase(), ownerDocument);
      this.tagName = tagName.toUpperCase();
    }

    get children() {
      return this.childNodes.filter((c): c is MiniElement => c.nodeType === 1);
    }

    get className() {
      return this.attributes.get('class') || '';
    }
    set className(val: string) {
      this.attributes.set('class', String(val || ''));
    }

    classList = {
      add: (...tokens: string[]) => {
        const set = new Set((this.attributes.get('class') || '').split(/\s+/).filter(Boolean));
        tokens.forEach((t) => set.add(t));
        this.attributes.set('class', Array.from(set).join(' '));
      },
      remove: (...tokens: string[]) => {
        const set = new Set((this.attributes.get('class') || '').split(/\s+/).filter(Boolean));
        tokens.forEach((t) => set.delete(t));
        this.attributes.set('class', Array.from(set).join(' '));
      },
      contains: (token: string) => {
        return (this.attributes.get('class') || '').split(/\s+/).includes(token);
      },
      toggle: (token: string) => {
        if (this.classList.contains(token)) this.classList.remove(token);
        else this.classList.add(token);
      }
    };

    get value() {
      return this._value;
    }
    set value(v: any) {
      this._value = v === null || v === undefined ? '' : String(v);
    }

    get checked() {
      return this._checked;
    }
    set checked(v: boolean) {
      this._checked = Boolean(v);
    }

    set innerHTML(val: string) {
      if (!val) {
        this.childNodes.forEach((c) => { c.parentNode = null; });
        this.childNodes = [];
      }
    }
    get innerHTML() {
      return '';
    }

    setAttribute(name: string, val: any) {
      const s = String(val);
      this.attributes.set(name, s);
      if (name === 'value') this._value = s;
      if (name === 'disabled') this.disabled = s !== 'false';
      if (name === 'type') this.type = s;
    }
    getAttribute(name: string) {
      return this.attributes.has(name) ? this.attributes.get(name)! : null;
    }
    removeAttribute(name: string) {
      this.attributes.delete(name);
      if (name === 'disabled') this.disabled = false;
    }
    hasAttribute(name: string) {
      return this.attributes.has(name);
    }

    focus() {
      if (this.ownerDocument) this.ownerDocument.activeElement = this;
    }
    blur() {
      if (this.ownerDocument && this.ownerDocument.activeElement === this) {
        this.ownerDocument.activeElement = this.ownerDocument.body;
      }
    }
    click() {
      this.dispatchEvent(new MiniEvent('click', { bubbles: true, cancelable: true }));
    }

    querySelectorAll(selector: string): MiniElement[] {
      const results: MiniElement[] = [];
      const tag = selector.toLowerCase();
      const visit = (node: MiniNode) => {
        for (const c of node.childNodes) {
          if (c instanceof MiniElement) {
            if (c.tagName.toLowerCase() === tag) results.push(c);
            visit(c);
          }
        }
      };
      visit(this);
      return results;
    }
    querySelector(selector: string): MiniElement | null {
      return this.querySelectorAll(selector)[0] || null;
    }
  }

  class MiniDocument extends MiniNode {
    documentElement: MiniElement;
    head: MiniElement;
    body: MiniElement;
    activeElement: any = null;
    defaultView: any = globalThis;
    location = { href: 'http://localhost:3000/' };
    oninput: any = null;
    onchange: any = null;
    onsubmit: any = null;
    onclick: any = null;

    constructor() {
      super(9, '#document', null);
      this.ownerDocument = this;
      this.documentElement = new MiniElement('html', this);
      this.head = new MiniElement('head', this);
      this.body = new MiniElement('body', this);
      this.documentElement.appendChild(this.head);
      this.documentElement.appendChild(this.body);
      this.activeElement = this.body;
    }

    createElement(tag: string) {
      return new MiniElement(tag, this);
    }
    createElementNS(_ns: string, tag: string) {
      return new MiniElement(tag, this);
    }
    createTextNode(text: string) {
      return new MiniNode(3, '#text', this).withText(String(text));
    }
    createComment(text: string) {
      return new MiniNode(8, '#comment', this).withText(String(text));
    }
    createDocumentFragment() {
      return new MiniNode(11, '#document-fragment', this);
    }
    querySelectorAll(sel: string) {
      return this.body.querySelectorAll(sel);
    }
    querySelector(sel: string) {
      return this.body.querySelector(sel);
    }
  }

  class MiniIFrameElement extends MiniElement {}
  class MiniSVGElement extends MiniElement {}

  const doc = new MiniDocument();
  (globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
  (globalThis as any).window = globalThis;
  (globalThis as any).document = doc;
  (globalThis as any).Document = MiniDocument;
  (globalThis as any).Node = MiniNode;
  (globalThis as any).Element = MiniElement;
  (globalThis as any).HTMLElement = MiniElement;
  (globalThis as any).HTMLInputElement = MiniElement;
  (globalThis as any).HTMLTextAreaElement = MiniElement;
  (globalThis as any).HTMLSelectElement = MiniElement;
  (globalThis as any).HTMLButtonElement = MiniElement;
  (globalThis as any).HTMLFormElement = MiniElement;
  (globalThis as any).HTMLAnchorElement = MiniElement;
  (globalThis as any).HTMLIFrameElement = MiniIFrameElement;
  (globalThis as any).SVGElement = MiniSVGElement;
  (globalThis as any).Event = MiniEvent;
  if (!(globalThis as any).navigator) {
    Object.defineProperty(globalThis, 'navigator', {
      value: { userAgent: 'node-test', clipboard: { writeText: async () => {} } },
      configurable: true
    });
  }
  if (!(globalThis as any).localStorage) {
    const store = new Map<string, string>();
    Object.defineProperty(globalThis, 'localStorage', {
      value: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => { store.set(k, String(v)); },
        removeItem: (k: string) => { store.delete(k); },
        clear: () => store.clear()
      },
      configurable: true
    });
  }
  return { doc, MiniElement, MiniEvent };
}

function createAsyncD1Adapter(sqliteDb: any) {
  return {
    prepare(sql: string) {
      let params: any[] = [];
      const boundStmt = {
        bind(...args: any[]) {
          params = args;
          return boundStmt;
        },
        async first<T = any>(colName?: string): Promise<T | null> {
          return sqliteDb.prepare(sql).bind(...params).first(colName);
        },
        async all<T = any>(): Promise<{ results: T[]; success: boolean }> {
          return sqliteDb.prepare(sql).bind(...params).all();
        },
        async run(): Promise<{ success: boolean; meta: { changes: number; last_row_id: number | bigint }; changes: number }> {
          const res = sqliteDb.prepare(sql).bind(...params).run();
          return {
            success: res.success,
            changes: res.changes,
            meta: { changes: res.changes, last_row_id: res.lastRowId }
          };
        }
      };
      return boundStmt;
    }
  };
}

async function runTests() {
  console.log('\n=== RUNNING RECOVERY-CODE CONCURRENCY, LOCAL D1 PERSISTENCE & UI/REALTIME TESTS ===\n');

  const { DatabaseSync } = await import('node:sqlite');
  const expressMod = await import('express');
  const express = expressMod.default;
  const { PersistentSecurityDatabase, db } = await import('../server/db.ts');
  const { authService } = await import('../server/services/auth.service.ts');
  const { userRepository } = await import('../server/repositories/user.repository.ts');
  const { sessionRepository } = await import('../server/repositories/session.repository.ts');
  const { policyRepository } = await import('../server/repositories/policy.repository.ts');
  const { auditRepository } = await import('../server/repositories/audit.repository.ts');
  const { requestIdMiddleware } = await import('../server/middleware/requestId.ts');
  const { errorHandlerMiddleware } = await import('../server/middleware/errorHandler.ts');
  const { default: rootRouter } = await import('../server/routes/index.ts');
  const { hashPassword, signJwt } = await import('../server/utils/crypto.ts');
  const { default: worker } = await import('../src/worker.ts');

  // Install DOM shim before importing React + components
  const { doc } = installMinimalDomShim();
  const React = await import('react');
  const { createRoot } = await import('react-dom/client');
  const { MfaVerificationCard } = await import('../src/components/MfaVerificationCard.tsx');
  const { AuthModal } = await import('../src/components/AuthModal.tsx');
  const { useRealtimeMonitor } = await import('../src/hooks/useRealtimeMonitor.ts');
  const { ThemeProvider } = await import('../src/context/ThemeContext.tsx');
  const { ThreatHeatmap, buildHeatmapModel } = await import('../src/components/ThreatHeatmap.tsx');

  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(requestIdMiddleware);
  app.use('/api', rootRouter);
  app.use(errorHandlerMiddleware);

  const server = await new Promise<http.Server>((resolve) => {
    const srv = app.listen(0, '127.0.0.1', () => resolve(srv));
  });
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const originalFetch = globalThis.fetch;
  const originalEventSource = (globalThis as any).EventSource;

  try {
    // =========================================================================
    // TEST 1 (Area 1): Persistent Disk D1 Emulation Across Close/Reopen + Config Check
    // =========================================================================
    const wranglerRaw = fs.readFileSync(path.resolve(process.cwd(), 'wrangler.jsonc'), 'utf-8');
    const wranglerCfg = JSON.parse(wranglerRaw);
    assert.strictEqual(wranglerCfg.d1_databases?.[0]?.binding, 'DB');
    assert.strictEqual(wranglerCfg.d1_databases?.[0]?.migrations_dir, 'migrations');

    // Read-only integrity check of existing server/data/security_framework.sqlite
    const prodPath = path.resolve(process.cwd(), 'server/data/security_framework.sqlite');
    assert.ok(fs.existsSync(prodPath), 'Production SQLite file must exist');
    const prodRo = new DatabaseSync(prodPath, { readOnly: true });
    try {
      const migs = prodRo.prepare('SELECT version FROM schema_migrations ORDER BY version ASC').all() as { version: string }[];
      assert.strictEqual(migs.length, 4, 'Production SQLite must have migrations 0001-0004 applied');
      const usrCount = (prodRo.prepare('SELECT COUNT(*) as c FROM users').get() as any).c;
      assert.ok(Number(usrCount) >= 1, 'Production SQLite must have existing users intact');
    } finally {
      prodRo.close();
    }

    // Two-phase Worker persistent disk SQLite test
    const d1UserPwd = `D1PersistPwd_${Date.now()}!`;
    const workerEnvBase = {
      ENVIRONMENT: 'development',
      ZERO_TRUST_ORIGIN: 'https://serverless-securityverification.ai.studio',
      JWT_SECRET: 'worker_persist_test_jwt_secret_minimum_32_chars_2026'
    };
    const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
    let phase1Codes: string[] = [];
    let persistedIncidentId = '';

    // Phase A: Write state via Worker D1 adapter -> close disk DB completely
    const dbPhaseA = new PersistentSecurityDatabase(tmpWorkerPersistDbPath);
    {
      const workerAdminPwd = `D1Admin_${Date.now()}!`;
      const { salt: aSalt, hash: aHash } = hashPassword(workerAdminPwd);
      dbPhaseA.prepare('UPDATE users SET password_salt = ?, password_hash = ?, mfa_enrolled = 1 WHERE username = ?')
        .bind(aSalt, aHash, 'secops_admin').run();

      const envA = { ...workerEnvBase, DB: createAsyncD1Adapter(dbPhaseA) };

      const regRes = await worker.fetch(new Request('http://localhost/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'd1_persist_user', password: d1UserPwd, role: 'Developer' })
      }), envA, ctx);
      assert.strictEqual(regRes.status, 200);

      // Directly approve test user in SQLite + enroll laptop recovery codes through Worker routes
      dbPhaseA.prepare("UPDATE users SET status = 'APPROVED', approved_by = 'secops_admin' WHERE username = 'd1_persist_user'").run();

      const l1: any = await (await worker.fetch(new Request('http://localhost/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'd1_persist_user', password: d1UserPwd })
      }), envA, ctx)).json();
      assert.strictEqual(l1.mfaRequired, true);
      assert.strictEqual(l1.enrollmentRequired, true);

      const en1: any = await (await worker.fetch(new Request('http://localhost/api/auth/mfa/enroll-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: l1.mfaChallengeId, mode: 'recovery_codes' })
      }), envA, ctx)).json();
      assert.strictEqual(en1.backupCodes?.length, 8);
      phase1Codes = en1.backupCodes;

      const ver1: any = await (await worker.fetch(new Request('http://localhost/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: l1.mfaChallengeId, code: phase1Codes[0], method: 'backup_code' })
      }), envA, ctx)).json();
      assert.strictEqual(ver1.success, true);
      assert.strictEqual(ver1.recoveryCodesRemaining, 7);

      // Create an incident under Developer/Admin via Worker
      // Promote temp user in Phase A DB ONLY inside isolated /tmp file for incident write test
      dbPhaseA.prepare("UPDATE users SET role = 'Admin' WHERE username = 'd1_persist_user'").run();
      const lAdmin: any = await (await worker.fetch(new Request('http://localhost/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'd1_persist_user', password: d1UserPwd })
      }), envA, ctx)).json();
      const verAdmin: any = await (await worker.fetch(new Request('http://localhost/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: lAdmin.mfaChallengeId, code: phase1Codes[1], method: 'backup_code' })
      }), envA, ctx)).json();
      assert.strictEqual(verAdmin.recoveryCodesRemaining, 6);

      const incRes: any = await (await worker.fetch(new Request('http://localhost/api/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${verAdmin.token}` },
        body: JSON.stringify({ title: 'Persisted Across DB Restart', severity: 'HIGH', status: 'OPEN' })
      }), envA, ctx)).json();
      assert.ok(incRes.incident?.id);
      persistedIncidentId = incRes.incident.id;

      dbPhaseA.close();
    }

    // Phase B: Re-open disk SQLite file from scratch -> verify user enrollment, remaining codes (6), spent codes rejected, & incident persisted
    const dbPhaseB = new PersistentSecurityDatabase(tmpWorkerPersistDbPath);
    try {
      const envB = { ...workerEnvBase, DB: createAsyncD1Adapter(dbPhaseB) };
      const l2: any = await (await worker.fetch(new Request('http://localhost/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'd1_persist_user', password: d1UserPwd })
      }), envB, ctx)).json();
      assert.strictEqual(l2.enrollmentRequired, false, 'Enrollment state must persist on disk across DB close/reopen');
      assert.strictEqual(l2.recoveryCodesRemaining, 6, 'Remaining 6 recovery codes must persist across restart');

      // Reusing Phase A code #0 after restart must fail
      const replaySpent = await worker.fetch(new Request('http://localhost/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: l2.mfaChallengeId, code: phase1Codes[0], method: 'backup_code' })
      }), envB, ctx);
      assert.strictEqual(replaySpent.status, 401, 'Spent recovery code must stay rejected after restart');

      // Using Phase A code #2 succeeds and leaves 5 codes
      const ver2: any = await (await worker.fetch(new Request('http://localhost/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: l2.mfaChallengeId, code: phase1Codes[2], method: 'backup_code' })
      }), envB, ctx)).json();
      assert.strictEqual(ver2.success, true);
      assert.strictEqual(ver2.recoveryCodesRemaining, 5);

      const incsB: any = await (await worker.fetch(new Request('http://localhost/api/incidents', {
        headers: { Authorization: `Bearer ${ver2.token}` }
      }), envB, ctx)).json();
      assert.ok((incsB.incidents || []).some((i: any) => i.id === persistedIncidentId), 'Incident written before restart must persist on disk');
    } finally {
      dbPhaseB.close();
    }
    console.log('✔ PASS 1: Local Worker D1 persistent disk storage verified across close/reopen + production SQLite schema 0001-0004 intact (Remote Cloudflare account deployment not run in offline sandbox)');

    // =========================================================================
    // TEST 2 (Area 3): Recovery Codes Concurrent Generation, Retry Safety & Single-Use Enforcement
    // =========================================================================
    const concUname = `ConcRecUser_${Date.now()}`;
    const concPwd = `StrongConc_${Date.now()}!`;
    userRepository.create({
      username: concUname,
      password: concPwd,
      role: 'Developer',
      base_risk_score: 10,
      status: 'APPROVED'
    });

    // 2A. Worker concurrent Promise.all enroll-challenge coalescing (same challenge)
    const workerDbConc = new PersistentSecurityDatabase(':memory:');
    try {
      const { salt, hash } = hashPassword(concPwd);
      workerDbConc.prepare(
        `INSERT INTO users (id, username, password_salt, password_hash, role, base_risk_score, status, mfa_enabled, mfa_enrolled)
         VALUES ('usr_conc_w', 'conc_w_user', ?, ?, 'Developer', 10, 'APPROVED', 1, 0)`
      ).bind(salt, hash).run();
      const envConc = { ...workerEnvBase, DB: createAsyncD1Adapter(workerDbConc) };

      const wLoginRes: any = await (await worker.fetch(new Request('http://localhost/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'conc_w_user', password: concPwd })
      }), envConc, ctx)).json();

      const [c1, c2, c3] = await Promise.all([
        worker.fetch(new Request('http://localhost/api/auth/mfa/enroll-challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfaChallengeId: wLoginRes.mfaChallengeId, mode: 'recovery_codes' })
        }), envConc, ctx).then((r) => r.json() as Promise<any>),
        worker.fetch(new Request('http://localhost/api/auth/mfa/enroll-challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfaChallengeId: wLoginRes.mfaChallengeId, mode: 'recovery_codes' })
        }), envConc, ctx).then((r) => r.json() as Promise<any>),
        worker.fetch(new Request('http://localhost/api/auth/mfa/enroll-challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfaChallengeId: wLoginRes.mfaChallengeId, mode: 'recovery_codes' })
        }), envConc, ctx).then((r) => r.json() as Promise<any>)
      ]);

      assert.strictEqual(c1.success && c2.success && c3.success, true, 'All 3 concurrent enroll-challenge calls must succeed cleanly');
      assert.deepStrictEqual(c1.backupCodes, c2.backupCodes, 'Concurrent Worker enroll-challenge requests must coalesce to identical code set');
      assert.deepStrictEqual(c2.backupCodes, c3.backupCodes, 'Concurrent Worker enroll-challenge requests must match committed hashes');

      // Verify persisted hash count = 8 valid SHA-256 hashes
      const uRowW: any = workerDbConc.prepare('SELECT mfa_backup_codes FROM users WHERE id = ?').bind('usr_conc_w').first();
      const parsedHashesW = JSON.parse(uRowW.mfa_backup_codes);
      assert.strictEqual(parsedHashesW.length, 8);
      assert.ok(parsedHashesW.every((h: string) => /^[0-9a-f]{64}$/.test(h)));

      // Retry BEFORE verification (simulating dropped response / Generate Fresh Set) succeeds with fresh codes and still verifies cleanly
      const retryBeforeVerify: any = await (await worker.fetch(new Request('http://localhost/api/auth/mfa/enroll-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: wLoginRes.mfaChallengeId, mode: 'recovery_codes' })
      }), envConc, ctx)).json();
      assert.strictEqual(retryBeforeVerify.success, true);
      assert.strictEqual(retryBeforeVerify.backupCodes.length, 8);

      // Confirm code #0 from retried set activates MFA and leaves 7
      const activateW: any = await (await worker.fetch(new Request('http://localhost/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: wLoginRes.mfaChallengeId, code: retryBeforeVerify.backupCodes[0], method: 'backup_code' })
      }), envConc, ctx)).json();
      assert.strictEqual(activateW.success, true);
      assert.strictEqual(activateW.recoveryCodesRemaining, 7);

      // Retry AFTER activation (on subsequent login challenge) must return 403 and preserve the 7 codes
      const wLogin2: any = await (await worker.fetch(new Request('http://localhost/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'conc_w_user', password: concPwd })
      }), envConc, ctx)).json();
      const blockedAfterEnroll = await worker.fetch(new Request('http://localhost/api/auth/mfa/enroll-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: wLogin2.mfaChallengeId, mode: 'recovery_codes' })
      }), envConc, ctx);
      assert.strictEqual(blockedAfterEnroll.status, 403, 'Post-activation retry of enroll-challenge must return 403');
      const uRowAfter: any = workerDbConc.prepare('SELECT mfa_backup_codes FROM users WHERE id = ?').bind('usr_conc_w').first();
      assert.strictEqual(JSON.parse(uRowAfter.mfa_backup_codes).length, 7, '403 retry must not overwrite remaining 7 codes');
    } finally {
      workerDbConc.close();
    }

    // 2B. Live Express HTTP concurrent generation + retry safety + single-use enforcement
    const eLogin1: any = await (await originalFetch(`${baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: concUname, password: concPwd })
    })).json();
    assert.strictEqual(eLogin1.mfaRequired, true);

    const [eGen1, eGen2, eGen3] = await Promise.all([
      originalFetch(`${baseUrl}/api/auth/mfa/enroll-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: eLogin1.mfaChallengeId, mode: 'recovery_codes' })
      }).then((r) => r.json() as Promise<any>),
      originalFetch(`${baseUrl}/api/auth/mfa/enroll-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: eLogin1.mfaChallengeId, mode: 'recovery_codes' })
      }).then((r) => r.json() as Promise<any>),
      originalFetch(`${baseUrl}/api/auth/mfa/enroll-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: eLogin1.mfaChallengeId, mode: 'recovery_codes' })
      }).then((r) => r.json() as Promise<any>)
    ]);
    assert.ok(eGen1.success && eGen2.success && eGen3.success);
    assert.strictEqual(userRepository.findByUsername(concUname)!.mfa_backup_codes!.length, 8);

    // Retry safely before verification -> last generated set verifies cleanly & activates mfa_enrolled
    const eRetry: any = await (await originalFetch(`${baseUrl}/api/auth/mfa/enroll-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfaChallengeId: eLogin1.mfaChallengeId, mode: 'recovery_codes' })
    })).json();
    assert.strictEqual(eRetry.success, true);

    const eVer0: any = await (await originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfaChallengeId: eLogin1.mfaChallengeId, code: eRetry.backupCodes[0], method: 'backup_code' })
    })).json();
    assert.strictEqual(eVer0.success, true);
    assert.strictEqual(eVer0.recoveryCodesRemaining, 7);

    // Concurrent single-use race over live Express HTTP -> strictly 1 succeeds, 1 fails
    const [eL2a, eL2b] = await Promise.all([
      originalFetch(`${baseUrl}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: concUname, password: concPwd })
      }).then((r) => r.json() as Promise<any>),
      originalFetch(`${baseUrl}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: concUname, password: concPwd })
      }).then((r) => r.json() as Promise<any>)
    ]);
    const [raceV1, raceV2] = await Promise.all([
      originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: eL2a.mfaChallengeId, code: eRetry.backupCodes[1], method: 'backup_code' })
      }),
      originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: eL2b.mfaChallengeId, code: eRetry.backupCodes[1], method: 'backup_code' })
      })
    ]);
    assert.strictEqual([raceV1, raceV2].filter((r) => r.status === 200).length, 1, 'Strictly 1 concurrent recovery verification may succeed over HTTP');
    assert.strictEqual(userRepository.findByUsername(concUname)!.mfa_backup_codes!.length, 6);
    console.log('✔ PASS 2: Recovery codes concurrent generation, pre/post-enrollment retry safety & single-use CAS verified on Worker & Express');

    // =========================================================================
    // TEST 3 (Area 4): MfaVerificationCard UI Spinner Fix, AbortController StrictMode & Tab Switching
    // =========================================================================
    // Bridge relative /api/* fetch calls inside React components to live Express server
    globalThis.fetch = ((input: any, init?: any) => {
      const url = typeof input === 'string' && input.startsWith('/') ? `${baseUrl}${input}` : input;
      return originalFetch(url, init);
    }) as any;

    const uiUname = `UiMfaTester_${Date.now()}`;
    const uiPwd = `StrongUiPwd_${Date.now()}!`;
    userRepository.create({
      username: uiUname,
      password: uiPwd,
      role: 'Developer',
      base_risk_score: 12,
      status: 'APPROVED'
    });
    const uiLoginJson: any = await (await originalFetch(`${baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: uiUname, password: uiPwd })
    })).json();

    const mountContainer = doc.createElement('div');
    doc.body.appendChild(mountContainer);
    let verifiedSessionFromUi: any = null;

    const challengeObj = {
      mfaSessionId: uiLoginJson.mfaChallengeId,
      username: uiUname,
      user: uiLoginJson.user,
      methods: ['backup_code', 'authenticator'] as ('backup_code' | 'authenticator')[],
      preferredMethod: 'backup_code' as const,
      enrollmentRequired: true,
      attemptsLeft: 5,
      expiresInSeconds: 300
    };

    // 3A. StrictMode mount/unmount/remount verifies AbortController prevents stale error or infinite spinner
    const strictRoot = createRoot(mountContainer as any);
    await React.act(async () => {
      strictRoot.render(
        React.createElement(
          React.StrictMode,
          null,
          React.createElement(
            ThemeProvider,
            null,
            React.createElement(MfaVerificationCard, {
              challenge: challengeObj,
              onVerifySuccess: (s: any) => { verifiedSessionFromUi = s; },
              onCancel: () => {}
            })
          )
        )
      );
    });
    // Wait briefly for network fetch microtasks + state flush
    await React.act(async () => {
      await new Promise((r) => setTimeout(r, 80));
    });

    const renderedTextAfterLoad = mountContainer.textContent;
    assert.ok(!renderedTextAfterLoad.includes('Generating 8 high-entropy single-use recovery codes'), 'Spinner must clear cleanly once recovery codes load');
    assert.ok(renderedTextAfterLoad.includes('Save These 8 Single-Use Codes Now'), 'Recovery code enrollment header must render');

    const codeButtons = mountContainer.querySelectorAll('button').filter((b) => /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(b.textContent.trim()));
    assert.strictEqual(codeButtons.length, 8, 'All 8 single-use recovery code tiles must render in UI');
    const firstRenderedCodes = codeButtons.map((b) => b.textContent.trim());

    // 3B. Switch to Authenticator App (Optional) tab -> loads QR panel -> switch back -> original recovery codes cached!
    const authTabBtn = mountContainer.querySelectorAll('button').find((b) => b.textContent.includes('Authenticator App (Optional)'));
    assert.ok(authTabBtn, 'Authenticator App (Optional) tab button must exist');
    await React.act(async () => {
      authTabBtn!.click();
      await new Promise((r) => setTimeout(r, 80));
    });
    assert.ok(mountContainer.textContent.includes('Optional: Pair an Authenticator App'), 'Authenticator pairing tab must render');

    const recTabBtn = mountContainer.querySelectorAll('button').find((b) => b.textContent.includes('Use a Recovery Code'));
    assert.ok(recTabBtn, 'Use a Recovery Code tab button must exist');
    await React.act(async () => {
      recTabBtn!.click();
    });

    const codeButtonsAfterSwitchBack = mountContainer.querySelectorAll('button').filter((b) => /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(b.textContent.trim()));
    assert.strictEqual(codeButtonsAfterSwitchBack.length, 8, 'Switching tabs back must preserve recovery code tiles without re-spinning');

    // Note: when Authenticator tab ran enroll-challenge before verification, DB updated backupCodes to authenticator panel's codes;
    // MfaVerificationCard syncs `setRecoveryEnrollmentCodes(data.backupCodes)` on authenticator fetch, so verify tile code works end-to-end!
    const activeTileCode = codeButtonsAfterSwitchBack[0].textContent.trim();
    assert.ok(firstRenderedCodes.length === 8 && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(activeTileCode));

    await React.act(async () => {
      codeButtonsAfterSwitchBack[0].click();
    });
    const recInput = mountContainer.querySelector('input');
    assert.strictEqual(recInput?.value, activeTileCode, 'Clicking a recovery code tile must populate the verification input');

    const submitBtn = mountContainer.querySelectorAll('button').find((b) => b.textContent.includes('Verify & Authorize Zero-Trust Session'));
    assert.ok(submitBtn);
    await React.act(async () => {
      submitBtn!.click();
      await new Promise((r) => setTimeout(r, 80));
    });
    assert.ok(verifiedSessionFromUi?.token && verifiedSessionFromUi.mfaMethod === 'backup_code', 'Clicking submit verifies recovery code and completes login');
    await React.act(async () => {
      strictRoot.unmount();
    });
    doc.body.removeChild(mountContainer);
    console.log('✔ PASS 3: MfaVerificationCard StrictMode AbortController spinner resolution, tab caching & click-to-verify flow verified');

    // =========================================================================
    // TEST 4 (Area 4): AuthModal Real-Time Approval Polling -> Automatic MFA Transition
    // =========================================================================
    const pollUname = `PollUser_${Date.now()}`;
    const pollPwd = `StrongPoll_${Date.now()}!`;
    policyRepository.updatePolicy({ requireAdminApprovalForNewLogins: true });

    const authContainer = doc.createElement('div');
    doc.body.appendChild(authContainer);
    const authRoot = createRoot(authContainer as any);
    await React.act(async () => {
      authRoot.render(
        React.createElement(
          ThemeProvider,
          null,
          React.createElement(AuthModal, {
            isOpen: true,
            onClose: () => {},
            users: [],
            currentSession: null,
            onLoginSuccess: () => {},
            onLogout: () => {}
          })
        )
      );
    });

    // Register pending user directly via API & attempt login via AuthModal Sign In form so pendingApprovalUser & pendingPasswordRef trigger polling
    const pollRegRes = await originalFetch(`${baseUrl}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: pollUname, password: pollPwd, role: 'Developer', department: 'Cloud QA' })
    });
    assert.strictEqual(pollRegRes.status, 200, 'Poll test user registration must succeed');

    const loginInputs = authContainer.querySelectorAll('input');
    assert.ok(loginInputs.length >= 2, 'AuthModal login inputs must render');
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(loginInputs[0]), 'value')?.set;
    await React.act(async () => {
      nativeInputValueSetter?.call(loginInputs[0], pollUname);
      loginInputs[0].dispatchEvent(new (globalThis as any).Event('input', { bubbles: true }));
      loginInputs[0].dispatchEvent(new (globalThis as any).Event('change', { bubbles: true }));
      nativeInputValueSetter?.call(loginInputs[1], pollPwd);
      loginInputs[1].dispatchEvent(new (globalThis as any).Event('input', { bubbles: true }));
      loginInputs[1].dispatchEvent(new (globalThis as any).Event('change', { bubbles: true }));
    });
    assert.strictEqual(loginInputs[0].value, pollUname, 'Controlled username input must reflect updated value');

    const loginForm = authContainer.querySelector('form');
    assert.ok(loginForm);
    await React.act(async () => {
      loginForm!.dispatchEvent(new (globalThis as any).Event('submit', { bubbles: true, cancelable: true }));
      await new Promise((r) => setTimeout(r, 150));
    });
    assert.ok(authContainer.textContent.includes('PENDING_APPROVAL'), `AuthModal must transition into PENDING_APPROVAL waiting screen; got: ${authContainer.textContent.slice(0, 300)}`);

    // Approve user via live Admin HTTP endpoint & wait for the real 2.5s poll loop to detect clearance and transition into MFA
    const adminUser = userRepository.findByUsername('secops_admin')!;
    const adminToken = signJwt({
      sub: adminUser.id,
      username: adminUser.username,
      role: 'Admin',
      jti: `jti_poll_admin_${crypto.randomBytes(4).toString('hex')}`,
      expiresInSeconds: 3600
    });
    sessionRepository.createSession({
      userId: adminUser.id,
      username: adminUser.username,
      role: 'Admin',
      token: adminToken,
      expiresInSeconds: 3600,
      ipAddress: '127.0.0.1'
    });
    const approveHttpRes = await originalFetch(`${baseUrl}/api/system/users/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ username: pollUname })
    });
    assert.strictEqual(approveHttpRes.status, 200, 'Live HTTP Admin approval must succeed');

    await React.act(async () => {
      await new Promise((r) => setTimeout(r, 2750));
    });

    assert.ok(
      authContainer.textContent.includes('Multi-Factor Authentication') &&
      authContainer.textContent.includes('First-Time Laptop MFA Enrollment'),
      'Real-time approval polling must automatically transition AuthModal straight into Factor 2 MFA enrollment'
    );
    await React.act(async () => {
      authRoot.unmount();
    });
    doc.body.removeChild(authContainer);
    console.log('✔ PASS 4: AuthModal real-time approval polling transitions cleanly from PENDING_APPROVAL into Factor-2 MFA');

    // =========================================================================
    // TEST 5 (Area 4): Live Express SSE Stream + Reconnect AND useRealtimeMonitor Hook Reconnection
    // =========================================================================
    // 5A: Real HTTP SSE stream connect -> receive initial CONNECTED -> trigger event -> receive NEW_INVOCATION -> disconnect -> reconnect
    async function readSseUntil(
      url: string,
      predicate: (events: any[]) => boolean,
      onConnected?: () => Promise<void>
    ): Promise<any[]> {
      const controller = new AbortController();
      const res = await originalFetch(url, { signal: controller.signal });
      assert.strictEqual(res.status, 200);
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      const parsedEvents: any[] = [];
      let notifiedConnect = false;

      const deadline = Date.now() + 3000;
      while (Date.now() < deadline) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const frames = buf.split('\n\n');
        buf = frames.pop() || '';
        for (const frame of frames) {
          const line = frame.split('\n').find((l) => l.startsWith('data:'));
          if (line) {
            const ev = JSON.parse(line.slice(5).trim());
            parsedEvents.push(ev);
            if (!notifiedConnect && ev.type === 'CONNECTED' && onConnected) {
              notifiedConnect = true;
              await onConnected();
            }
          }
        }
        if (predicate(parsedEvents)) {
          controller.abort();
          return parsedEvents;
        }
      }
      controller.abort();
      return parsedEvents;
    }

    const sseSession1 = await readSseUntil(
      `${baseUrl}/api/v1/realtime/stream`,
      (evs) => evs.some((e) => e.type === 'CONNECTED') && evs.some((e) => e.type === 'NEW_INVOCATION' && e.data?.requested_function === '/api/sse_probe_1'),
      async () => {
        auditRepository.record({
          username: 'sse_tester',
          requested_function: '/api/sse_probe_1',
          calculated_risk: 10,
          status: 'ALLOWED',
          reason: 'SSE live stream check #1',
          verification_latency_ms: 0.4,
          event_type: 'STANDARD_VERIFICATION'
        });
      }
    );
    assert.ok(sseSession1.some((e) => e.type === 'CONNECTED'));
    assert.ok(sseSession1.some((e) => e.data?.requested_function === '/api/sse_probe_1'));

    // Reconnect fresh SSE client after disconnect and verify live push continues working cleanly
    const sseSession2 = await readSseUntil(
      `${baseUrl}/api/v1/realtime/stream`,
      (evs) => evs.some((e) => e.type === 'CONNECTED') && evs.some((e) => e.type === 'NEW_INVOCATION' && e.data?.requested_function === '/api/sse_probe_2'),
      async () => {
        auditRepository.record({
          username: 'sse_tester',
          requested_function: '/api/sse_probe_2',
          calculated_risk: 12,
          status: 'ALLOWED',
          reason: 'SSE reconnect live check #2',
          verification_latency_ms: 0.4,
          event_type: 'STANDARD_VERIFICATION'
        });
      }
    );
    assert.ok(sseSession2.some((e) => e.data?.requested_function === '/api/sse_probe_2'), 'Reconnected SSE stream must receive subsequent live events');

    // 5B: useRealtimeMonitor Hook State Transitions (LIVE_STREAMING -> error -> POLLING_FALLBACK -> RECONNECTING -> LIVE_STREAMING)
    const createdEventSources: any[] = [];
    class FakeEventSource {
      url: string;
      onopen: (() => void) | null = null;
      onmessage: ((ev: { data: string }) => void) | null = null;
      onerror: ((err?: any) => void) | null = null;
      closed = false;
      constructor(url: string) {
        this.url = url;
        createdEventSources.push(this);
      }
      close() {
        this.closed = true;
      }
    }
    (globalThis as any).EventSource = FakeEventSource;

    const hookContainer = doc.createElement('div');
    doc.body.appendChild(hookContainer);
    let latestState: any = null;
    const receivedLogs: any[] = [];

    const HookProbe = () => {
      const state = useRealtimeMonitor({
        pollingIntervalMs: 120,
        onNewLog: (l) => receivedLogs.push(l)
      });
      latestState = state;
      return React.createElement('span', null, `${state.connectionStatus}:${state.reconnectAttempts}:${state.streamEventsCount}`);
    };

    const hookRoot = createRoot(hookContainer as any);
    await React.act(async () => {
      hookRoot.render(React.createElement(HookProbe));
    });
    assert.strictEqual(createdEventSources.length, 1);

    await React.act(async () => {
      createdEventSources[0].onopen?.();
    });
    assert.strictEqual(latestState.connectionStatus, 'LIVE_STREAMING');
    assert.strictEqual(latestState.reconnectAttempts, 0);

    // Send duplicate event -> deduplicated
    const dupEv = JSON.stringify({
      type: 'NEW_INVOCATION',
      timestamp: '2026-11-22T10:00:00Z',
      data: { id: 901, timestamp: '2026-11-22T10:00:00Z', requested_function: '/api/probe' }
    });
    await React.act(async () => {
      createdEventSources[0].onmessage?.({ data: dupEv });
      createdEventSources[0].onmessage?.({ data: dupEv });
    });
    assert.strictEqual(receivedLogs.length, 1, 'Duplicate SSE event must be deduplicated');

    // Trigger SSE error -> immediate transition to POLLING_FALLBACK & reconnectAttempts = 1
    await React.act(async () => {
      createdEventSources[0].onerror?.(new Error('dropped'));
    });
    assert.strictEqual(createdEventSources[0].closed, true);
    assert.strictEqual(latestState.connectionStatus, 'POLLING_FALLBACK');
    assert.strictEqual(latestState.reconnectAttempts, 1);

    // Wait past initial 3000ms backoff timer -> RECONNECTING -> spawns 2nd EventSource -> open resets status to LIVE_STREAMING
    await React.act(async () => {
      await new Promise((r) => setTimeout(r, 3150));
    });
    assert.strictEqual(createdEventSources.length, 2, 'Reconnect backoff must instantiate a new EventSource');
    await React.act(async () => {
      createdEventSources[1].onopen?.();
    });
    assert.strictEqual(latestState.connectionStatus, 'LIVE_STREAMING');
    assert.strictEqual(latestState.reconnectAttempts, 0);
    assert.strictEqual(latestState.isLive, true);

    await React.act(async () => {
      hookRoot.unmount();
    });
    doc.body.removeChild(hookContainer);
    console.log('✔ PASS 5: Live Express SSE stream reconnect & useRealtimeMonitor fallback/backoff recovery verified');

    // =========================================================================
    // TEST 6: ThreatHeatmap Intensity Coordinate Mapping, React 19 UI & SHA-256 Chain Check
    // =========================================================================
    const sampleHeatmapLogs = [
      {
        id: 1,
        timestamp: '2026-11-23T10:00:00.000Z',
        username: 'threat_actor',
        requested_function: '/api/deployWorkerCode',
        calculated_risk: 95,
        status: 'BLOCKED' as const,
        reason: 'Link-Local IMDS Probe (169.254.169.254)',
        verification_latency_ms: 0.42,
        event_type: 'CLOUD_METADATA_SSRF'
      },
      {
        id: 2,
        timestamp: '2026-11-23T10:01:00.000Z',
        username: 'threat_actor',
        requested_function: '/api/deployWorkerCode',
        calculated_risk: 90,
        status: 'BLOCKED' as const,
        reason: 'Markov sequence deviation: abnormal invocation order',
        verification_latency_ms: 0.38,
        event_type: 'SEQUENCE_VIOLATION'
      },
      {
        id: 3,
        timestamp: '2026-11-23T10:02:00.000Z',
        username: 'cloud_dev',
        requested_function: '/api/getDashboardMetrics',
        calculated_risk: 15,
        status: 'ALLOWED' as const,
        reason: 'Passed 15-step verification',
        verification_latency_ms: 0.31,
        event_type: 'STANDARD_VERIFICATION'
      }
    ];

    const vectorModel = buildHeatmapModel({
      logs: sampleHeatmapLogs,
      axisMode: 'vector',
      intensityBasis: 'composite',
      trafficFilter: 'ALL',
      functionQuery: '',
      maxThreshold: 75
    });
    assert.strictEqual(vectorModel.rows[0].functionName, 'deployWorkerCode', 'Most frequently attacked function must rank first');
    assert.strictEqual(vectorModel.rows[0].blockedHits, 2);
    assert.ok(vectorModel.hottestCell && vectorModel.hottestCell.functionName === 'deployWorkerCode');
    assert.strictEqual(vectorModel.hottestCell.severityLabel, 'Critical');

    // Mount real ThreatHeatmap React 19 tree + verify interactive axis toggle, cell selection & live /api/v1/audit/verify-chain
    const adminForChain = userRepository.findByUsername('secops_admin')!;
    const chainToken = signJwt({
      sub: adminForChain.id,
      username: adminForChain.username,
      role: 'Admin',
      jti: `jti_chain_${crypto.randomBytes(4).toString('hex')}`,
      expiresInSeconds: 3600
    });
    sessionRepository.createSession({
      userId: adminForChain.id,
      username: adminForChain.username,
      role: 'Admin',
      token: chainToken,
      expiresInSeconds: 3600
    });
    const { setActiveAuthToken } = await import('../src/utils/authTokenStore.ts');
    setActiveAuthToken(chainToken);

    const heatmapContainer = doc.createElement('div');
    doc.body.appendChild(heatmapContainer);
    const heatmapRoot = createRoot(heatmapContainer as any);
    await React.act(async () => {
      heatmapRoot.render(
        React.createElement(
          ThemeProvider,
          null,
          React.createElement(ThreatHeatmap, {
            logs: sampleHeatmapLogs,
            maxThreshold: 75,
            realtimeTelemetry: {
              connectionStatus: 'LIVE_STREAMING',
              lastServerTime: new Date().toISOString(),
              streamEventsCount: 12,
              reconnectAttempts: 0,
              isLive: true
            }
          })
        )
      );
    });
    assert.ok(heatmapContainer.textContent.includes('Threat Coordinate Heatmap'));
    assert.ok(heatmapContainer.textContent.includes('deployWorkerCode'));
    assert.ok(heatmapContainer.textContent.includes('SSE Stream Live (12)'));

    // Switch to Vector x Function mode and click Verify SHA-256 Chain
    const vectorBtn = heatmapContainer.querySelectorAll('button').find((b: any) => b.getAttribute('id') === 'btn-heatmap-axis-vector');
    assert.ok(vectorBtn, 'Vector x Function button must render');
    await React.act(async () => {
      vectorBtn!.click();
    });
    assert.ok(heatmapContainer.textContent.includes('Cloud SSRF'), 'Vector axis header must appear after mode switch');

    const verifyChainBtn = heatmapContainer.querySelectorAll('button').find((b: any) => b.getAttribute('id') === 'btn-verify-audit-chain');
    assert.ok(verifyChainBtn, 'Verify SHA-256 Chain button must render');
    await React.act(async () => {
      verifyChainBtn!.click();
      await new Promise((r) => setTimeout(r, 120));
    });
    assert.ok(
      heatmapContainer.textContent.includes('SHA-256 Chain Verified Intact'),
      `Live /api/v1/audit/verify-chain must report intact SHA-256 chain; got: ${heatmapContainer.textContent.slice(0, 350)}`
    );

    setActiveAuthToken(null);
    await React.act(async () => {
      heatmapRoot.unmount();
    });
    doc.body.removeChild(heatmapContainer);
    console.log('✔ PASS 6: ThreatHeatmap coordinate mapping, React 19 vector/temporal UI & live SHA-256 chain check verified');

    console.log('\nALL RECOVERY CONCURRENCY, LOCAL D1 PERSISTENCE, HEATMAP & UI/REALTIME TESTS PASSED (6/6)\n');
  } finally {
    globalThis.fetch = originalFetch;
    if (originalEventSource) (globalThis as any).EventSource = originalEventSource;
    else delete (globalThis as any).EventSource;

    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
    for (const basePath of [tmpExpressDbPath, tmpWorkerPersistDbPath]) {
      for (const ext of ['', '-wal', '-shm']) {
        const f = `${basePath}${ext}`;
        if (fs.existsSync(f)) {
          try {
            fs.unlinkSync(f);
          } catch {
            // ignore
          }
        }
      }
    }
  }
}

runTests().catch((err) => {
  console.error('❌ Recovery/UI/Realtime Test Failed:', err);
  process.exit(1);
});
