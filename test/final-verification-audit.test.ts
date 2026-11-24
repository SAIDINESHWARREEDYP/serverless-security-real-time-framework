/**
 * Pre-Finalization Independent Verification Suite (5 Checkpoints):
 * 1. Audit-Chain Integrity: Full-ledger SHA-256 verification (>200 rows back), trusted genesis,
 *    HMAC anchor sealing, and tamper detection (change, delete, reorder, insert, genesis/tail attacks).
 * 2. Threat Heatmap Accuracy: Exact 1:1 DB-to-overview-to-heatmap coordinate, score, block-rate,
 *    latency (no synthetic fallbacks), and function-ranking verification.
 * 3. Concurrent Recovery-Code Safety: Express + Worker concurrent enroll-challenge coalescing,
 *    forceRefresh, pre/post-enrollment retry safety, single-use consumption, and dual-race CAS.
 * 4. SSE Reliability: Live stream handshake (latestAuditId), disconnect/reconnect, duplicate event
 *    deduplication, and POLLING_FALLBACK missed-event recovery without duplication on reconnect.
 * 5. Cloudflare Worker & Local File-Backed D1 Verification: Optional INITIAL_ADMIN_PASSWORD bootstrap,
 *    200-event overview query, >200-record Worker /api/v1/audit/verify-chain & tamper detection across
 *    DB close/reopen. (Remote Cloudflare deployment is not tested in offline sandbox.)
 */

import assert from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

const tmpExpressDbPath = `/tmp/test_final_express_${Date.now()}_${crypto.randomBytes(3).toString('hex')}.sqlite`;
const tmpWorkerDbPath = `/tmp/test_final_worker_d1_${Date.now()}_${crypto.randomBytes(3).toString('hex')}.sqlite`;
const tmpWorkerGovDbPath = `/tmp/test_final_worker_gov_${Date.now()}_${crypto.randomBytes(3).toString('hex')}.sqlite`;
process.env.SECURITY_DB_PATH = tmpExpressDbPath;

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
    stopPropagation() {}
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
        for (const fc of [...child.childNodes]) this.insertBefore(fc, ref);
        return child;
      }
      if (child.parentNode) child.parentNode.removeChild(child);
      child.parentNode = this;
      if (!ref) this.childNodes.push(child);
      else {
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
    get nodeValue(): string | null {
      if (this.nodeType === 3 || this.nodeType === 8) return this._text;
      return null;
    }
    set nodeValue(v: string | null) {
      if (this.nodeType === 3 || this.nodeType === 8) {
        this._text = v === null || v === undefined ? '' : String(v);
      }
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
          for (const h of Array.from(handlers)) h.call(cur, event);
        }
        const propHandler = (cur as any)[`on${event.type}`];
        if (typeof propHandler === 'function') propHandler.call(cur, event);
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
        get(t, p) { return p in t ? (t as any)[p] : ''; },
        set(t, p, v) { (t as any)[p] = v; return true; }
      }
    );
    _value = '';
    _checked = false;
    disabled = false;
    type = '';

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
      contains: (token: string) => (this.attributes.get('class') || '').split(/\s+/).includes(token),
      toggle: (token: string) => {
        if (this.classList.contains(token)) this.classList.remove(token);
        else this.classList.add(token);
      }
    };
    get value() { return this._value; }
    set value(v: any) { this._value = v === null || v === undefined ? '' : String(v); }
    get checked() { return this._checked; }
    set checked(v: boolean) { this._checked = Boolean(v); }
    set innerHTML(val: string) {
      if (!val) {
        this.childNodes.forEach((c) => { c.parentNode = null; });
        this.childNodes = [];
      }
    }
    get innerHTML() { return ''; }
    setAttribute(name: string, val: any) {
      const s = String(val);
      this.attributes.set(name, s);
      if (name === 'value') this._value = s;
      if (name === 'disabled') this.disabled = s !== 'false';
      if (name === 'type') this.type = s;
    }
    getAttribute(name: string) { return this.attributes.has(name) ? this.attributes.get(name)! : null; }
    removeAttribute(name: string) {
      this.attributes.delete(name);
      if (name === 'disabled') this.disabled = false;
    }
    hasAttribute(name: string) { return this.attributes.has(name); }
    focus() { if (this.ownerDocument) this.ownerDocument.activeElement = this; }
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
      const trimmed = selector.trim();
      const attrMatch = /^\[([^=\]]+)=["']?([^"'\]]+)["']?\]$/.exec(trimmed);
      const visit = (node: MiniNode) => {
        for (const c of node.childNodes) {
          if (c instanceof MiniElement) {
            let matched = false;
            if (trimmed.startsWith('#')) {
              matched = c.attributes.get('id') === trimmed.slice(1);
            } else if (trimmed.startsWith('.')) {
              const cls = trimmed.slice(1);
              matched = (c.attributes.get('class') || '').split(/\s+/).includes(cls);
            } else if (attrMatch) {
              matched = c.attributes.get(attrMatch[1]) === attrMatch[2];
            } else {
              matched = c.tagName.toLowerCase() === trimmed.toLowerCase();
            }
            if (matched) results.push(c);
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
    createElement(tag: string) { return new MiniElement(tag, this); }
    createElementNS(_ns: string, tag: string) { return new MiniElement(tag, this); }
    createTextNode(text: string) { return new MiniNode(3, '#text', this).withText(String(text)); }
    createComment(text: string) { return new MiniNode(8, '#comment', this).withText(String(text)); }
    createDocumentFragment() { return new MiniNode(11, '#document-fragment', this); }
    querySelectorAll(sel: string) { return this.body.querySelectorAll(sel); }
    querySelector(sel: string) { return this.body.querySelector(sel); }
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
  return { doc };
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
        },
        _runSync() {
          const trimmed = sql.trim().toUpperCase();
          if (trimmed.startsWith('SELECT') || trimmed.startsWith('PRAGMA')) {
            const allRes = sqliteDb.prepare(sql).bind(...params).all();
            return { success: allRes.success, results: allRes.results, meta: { changes: 0, last_row_id: 0 } };
          }
          const res = sqliteDb.prepare(sql).bind(...params).run();
          return {
            success: res.success,
            results: [],
            changes: res.changes,
            meta: { changes: res.changes, last_row_id: res.lastRowId }
          };
        }
      };
      return boundStmt;
    },
    async batch(statements: any[]) {
      return sqliteDb.transaction(() => {
        return statements.map((stmt) => stmt._runSync());
      });
    }
  };
}

async function runTests() {
  console.log('\n=== RUNNING 5-POINT PRE-FINALIZATION VERIFICATION SUITE ===\n');

  const expressMod = await import('express');
  const express = expressMod.default;
  const { PersistentSecurityDatabase, db } = await import('../server/db.ts');
  const { auditRepository, TRUSTED_AUDIT_GENESIS_HASH } = await import('../server/repositories/audit.repository.ts');
  const { userRepository } = await import('../server/repositories/user.repository.ts');
  const { sessionRepository } = await import('../server/repositories/session.repository.ts');
  const { requestIdMiddleware } = await import('../server/middleware/requestId.ts');
  const { errorHandlerMiddleware } = await import('../server/middleware/errorHandler.ts');
  const { default: rootRouter } = await import('../server/routes/index.ts');
  const { signJwt } = await import('../server/utils/crypto.ts');
  const { default: worker } = await import('../src/worker.ts');

  const { doc } = installMinimalDomShim();
  const React = await import('react');
  const { createRoot } = await import('react-dom/client');
  const { ThemeProvider } = await import('../src/context/ThemeContext.tsx');
  const { ThreatHeatmap, buildHeatmapModel } = await import('../src/components/ThreatHeatmap.tsx');
  const { useRealtimeMonitor } = await import('../src/hooks/useRealtimeMonitor.ts');
  const { setActiveAuthToken } = await import('../src/utils/authTokenStore.ts');

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

  const adminUser = userRepository.findByUsername('secops_admin')!;
  const adminToken = signJwt({
    sub: adminUser.id,
    username: adminUser.username,
    role: 'Admin',
    jti: `jti_final_${crypto.randomBytes(4).toString('hex')}`,
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

  try {
    // =========================================================================
    // CHECKPOINT 1: Full-Ledger Audit-Chain Integrity (>200 Records + Tampering)
    // =========================================================================
    auditRepository.clear();
    const recorded250: any[] = [];
    for (let i = 1; i <= 250; i++) {
      recorded250.push(
        auditRepository.record({
          username: i % 3 === 0 ? 'threat_actor' : 'cloud_dev',
          requested_function: i % 5 === 0 ? '/api/deployWorkerCode' : '/api/getDashboardMetrics',
          calculated_risk: i % 5 === 0 ? 85 : 15,
          status: i % 5 === 0 ? 'BLOCKED' : 'ALLOWED',
          reason: `Chain baseline record #${i}`,
          verification_latency_ms: 0.25,
          event_type: i % 5 === 0 ? 'SEQUENCE_VIOLATION' : 'STANDARD_VERIFICATION'
        })
      );
    }

    const cleanChain = auditRepository.verifyIntegrityChain();
    assert.strictEqual(cleanChain.chainIntact, true, '250-record fresh chain must verify intact');
    assert.strictEqual(cleanChain.fullLedgerVerified, true);
    assert.strictEqual(cleanChain.genesisVerified, true, 'Genesis prev_hash must match trusted 64-zero anchor');
    assert.strictEqual(cleanChain.trustedGenesisHash, TRUSTED_AUDIT_GENESIS_HASH);
    assert.strictEqual(cleanChain.anchorPresent, true);
    assert.strictEqual(cleanChain.anchorVerified, true);
    assert.strictEqual(cleanChain.totalInLedger, 250);
    assert.strictEqual(cleanChain.totalChecked, 250);
    assert.strictEqual(cleanChain.verifiedCount, 250);
    assert.strictEqual(cleanChain.brokenLinks.length, 0);

    // Live HTTP endpoint defaults to full-ledger verification (>200 rows)
    const chainHttpRes: any = await (await originalFetch(`${baseUrl}/api/v1/audit/verify-chain`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    })).json();
    assert.strictEqual(chainHttpRes.chainIntact, true);
    assert.strictEqual(chainHttpRes.totalChecked, 250);
    assert.strictEqual(chainHttpRes.genesisVerified, true);

    // Helper to restore the clean 250-row ledger & anchor before each isolated attack vector
    const snapshotRows = db.prepare('SELECT * FROM audit_events ORDER BY id ASC').all<any>().results;
    const snapshotAnchor = db.prepare('SELECT * FROM audit_chain_anchor WHERE id = 1').first<any>();
    const restoreClean250 = () => {
      db.exec('DELETE FROM audit_events; DELETE FROM audit_chain_anchor;');
      const ins = db.prepare(
        `INSERT INTO audit_events (id, timestamp, username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type, integrity_hash, prev_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const r of snapshotRows) {
        ins.bind(
          r.id, r.timestamp, r.username, r.requested_function, r.calculated_risk, r.status,
          r.reason, r.verification_latency_ms, r.event_type, r.integrity_hash, r.prev_hash, r.created_at
        ).run();
      }
      db.prepare(
        `INSERT INTO audit_chain_anchor (id, genesis_hash, head_id, head_hash, record_count, anchor_hmac, updated_at)
         VALUES (1, ?, ?, ?, ?, ?, ?)`
      ).bind(
        snapshotAnchor.genesis_hash,
        snapshotAnchor.head_id,
        snapshotAnchor.head_hash,
        snapshotAnchor.record_count,
        snapshotAnchor.anchor_hmac,
        snapshotAnchor.updated_at
      ).run();
    };

    // 1A. Change a field on row #10 (240 records back, >200 records old)
    const row10 = snapshotRows[9];
    db.prepare('UPDATE audit_events SET calculated_risk = 0, reason = ? WHERE id = ?')
      .bind('Tampered old history entry', row10.id).run();
    const resChangeOld = auditRepository.verifyIntegrityChain();
    assert.strictEqual(resChangeOld.chainIntact, false, 'Changing record >200 rows back must break chain');
    assert.ok(resChangeOld.brokenLinks.some((b) => b.id === row10.id && b.reason === 'HASH_MISMATCH'));
    restoreClean250();

    // 1B. Delete middle row #10 (>200 records back)
    db.prepare('DELETE FROM audit_events WHERE id = ?').bind(row10.id).run();
    const resDeleteOld = auditRepository.verifyIntegrityChain();
    assert.strictEqual(resDeleteOld.chainIntact, false, 'Deleting record >200 rows back must break chain');
    assert.ok(resDeleteOld.brokenLinks.some((b) => b.id === snapshotRows[10].id && b.reason === 'CHAIN_LINK_BREAK'));
    assert.ok(resDeleteOld.brokenLinks.some((b) => b.reason === 'TAIL_TRUNCATION'));
    restoreClean250();

    // 1C. Reorder rows #10 and #11 (>200 records back) by swapping timestamps/data between ids
    const row11 = snapshotRows[10];
    db.prepare('UPDATE audit_events SET timestamp = ?, created_at = ?, reason = ?, integrity_hash = ?, prev_hash = ? WHERE id = ?')
      .bind(row11.timestamp, row11.created_at, row11.reason, row11.integrity_hash, row11.prev_hash, row10.id).run();
    db.prepare('UPDATE audit_events SET timestamp = ?, created_at = ?, reason = ?, integrity_hash = ?, prev_hash = ? WHERE id = ?')
      .bind(row10.timestamp, row10.created_at, row10.reason, row10.integrity_hash, row10.prev_hash, row11.id).run();
    const resReorderOld = auditRepository.verifyIntegrityChain();
    assert.strictEqual(resReorderOld.chainIntact, false, 'Reordering rows >200 records back must be detected');
    assert.ok(resReorderOld.brokenLinks.some((b) => b.reason === 'CHAIN_LINK_BREAK' || b.reason === 'ORDER_ANOMALY' || b.reason === 'HASH_MISMATCH'));
    restoreClean250();

    // 1D. Insert synthetic row in middle between row #10 and #11 (using row10's hash as prev_hash)
    const synthTs = new Date(Date.parse(row10.timestamp) + 1).toISOString();
    const synthReason = 'Synthetic injected audit event';
    const synthHash = crypto
      .createHash('sha256')
      .update(`${synthTs}|attacker|/api/backdoor|0|ALLOWED|${synthReason}|${row10.integrity_hash}`)
      .digest('hex');
    const midId = row10.id * 1000; // Put wait: to test insertion in middle by id order, give id between two consecutive rows!
    // Shift row #11..#250 IDs up by +1? Simpler: delete #11? No, create synthetic row with prev_hash = row10.integrity_hash & verify id between 10 and 11:
    // Use id = row10.id + 1 after moving rows >= row11.id up, OR delete nothing and shift id:
    db.prepare('UPDATE audit_events SET id = id + 10000 WHERE id >= ?').bind(row11.id).run();
    db.prepare('UPDATE audit_events SET id = id - 9999 WHERE id > 10000').run();
    db.prepare(
      `INSERT INTO audit_events (id, timestamp, username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type, integrity_hash, prev_hash, created_at)
       VALUES (?, ?, 'attacker', '/api/backdoor', 0, 'ALLOWED', ?, 0.1, 'STANDARD_VERIFICATION', ?, ?, ?)`
    ).bind(row10.id + 1, synthTs, synthReason, synthHash, row10.integrity_hash, synthTs).run();
    const resInsertMid = auditRepository.verifyIntegrityChain();
    assert.strictEqual(resInsertMid.chainIntact, false, 'Inserting synthetic row in middle must be detected');
    assert.ok(resInsertMid.brokenLinks.some((b) => b.reason === 'CHAIN_LINK_BREAK'));
    assert.ok(resInsertMid.brokenLinks.some((b) => b.reason === 'UNTRACKED_INSERTION'));
    restoreClean250();

    // 1E. Untrusted Genesis: delete genesis row #1 -> next row has non-genesis prev_hash
    db.prepare('DELETE FROM audit_events WHERE id = ?').bind(snapshotRows[0].id).run();
    const resGenesisDeleted = auditRepository.verifyIntegrityChain();
    assert.strictEqual(resGenesisDeleted.chainIntact, false, 'Deleting genesis row must fail trusted genesis check');
    assert.strictEqual(resGenesisDeleted.genesisVerified, false);
    assert.ok(resGenesisDeleted.brokenLinks.some((b) => b.reason === 'GENESIS_MISMATCH'));
    restoreClean250();

    // 1F. Tail truncation: delete last row #250 -> anchor catches tail deletion
    db.prepare('DELETE FROM audit_events WHERE id = ?').bind(snapshotRows[249].id).run();
    const resTailDelete = auditRepository.verifyIntegrityChain();
    assert.strictEqual(resTailDelete.chainIntact, false, 'Deleting tail row #250 must be caught by HMAC anchor');
    assert.strictEqual(resTailDelete.anchorVerified, false);
    assert.ok(resTailDelete.brokenLinks.some((b) => b.reason === 'TAIL_TRUNCATION'));
    restoreClean250();

    // 1G. Untracked SQL append at end with valid self-chained SHA-256 -> anchor catches untracked insertion
    const head250 = snapshotRows[249];
    const appendTs = new Date(Date.parse(head250.timestamp) + 1000).toISOString();
    const appendReason = 'Forged self-chained tail record';
    const appendHash = crypto
      .createHash('sha256')
      .update(`${appendTs}|forger|/api/deployWorkerCode|0|ALLOWED|${appendReason}|${head250.integrity_hash}`)
      .digest('hex');
    db.prepare(
      `INSERT INTO audit_events (timestamp, username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type, integrity_hash, prev_hash, created_at)
       VALUES (?, 'forger', '/api/deployWorkerCode', 0, 'ALLOWED', ?, 0.1, 'STANDARD_VERIFICATION', ?, ?, ?)`
    ).bind(appendTs, appendReason, appendHash, head250.integrity_hash, appendTs).run();
    const resTailAppend = auditRepository.verifyIntegrityChain();
    assert.strictEqual(resTailAppend.chainIntact, false, 'Appending self-chained row outside repository must be caught by HMAC anchor');
    assert.strictEqual(resTailAppend.anchorVerified, false);
    assert.ok(resTailAppend.brokenLinks.some((b) => b.reason === 'UNTRACKED_INSERTION'));
    restoreClean250();

    console.log('✔ PASS 1 (Audit Chain): 250-record full-ledger check, trusted genesis, HMAC anchor & tamper detection >200 rows back (change/delete/reorder/insert/genesis/tail) verified');

    // =========================================================================
    // CHECKPOINT 2: Heatmap Accuracy (100% DB-Backed Metrics & Coordinates)
    // =========================================================================
    auditRepository.clear();
    const hmRecords = [
      // deployWorkerCode: 3 SSRF BLOCKED, 2 Sequence BLOCKED, 2 ALLOWED (latency=0 on one, 0.5 on another) => 7 total, 5 blocked
      { username: 'attacker1', requested_function: '/api/deployWorkerCode', calculated_risk: 95, status: 'BLOCKED' as const, reason: 'SSRF 169.254.169.254 probe', verification_latency_ms: 0.4, event_type: 'CLOUD_METADATA_SSRF' },
      { username: 'attacker1', requested_function: '/api/deployWorkerCode', calculated_risk: 95, status: 'BLOCKED' as const, reason: 'SSRF 169.254.169.254 probe', verification_latency_ms: 0.6, event_type: 'CLOUD_METADATA_SSRF' },
      { username: 'attacker2', requested_function: '/api/deployWorkerCode', calculated_risk: 92, status: 'BLOCKED' as const, reason: 'SSRF metadata.google.internal', verification_latency_ms: 0.5, event_type: 'CLOUD_METADATA_SSRF' },
      { username: 'attacker1', requested_function: '/api/deployWorkerCode', calculated_risk: 90, status: 'BLOCKED' as const, reason: 'Markov sequence anomaly', verification_latency_ms: 0.3, event_type: 'SEQUENCE_VIOLATION' },
      { username: 'attacker1', requested_function: '/api/deployWorkerCode', calculated_risk: 85, status: 'BLOCKED' as const, reason: 'Markov sequence anomaly', verification_latency_ms: 0.3, event_type: 'SEQUENCE_VIOLATION' },
      { username: 'cloud_dev', requested_function: '/api/deployWorkerCode', calculated_risk: 20, status: 'ALLOWED' as const, reason: 'Valid deploy', verification_latency_ms: 0, event_type: 'STANDARD_VERIFICATION' },
      { username: 'cloud_dev', requested_function: '/api/deployWorkerCode', calculated_risk: 20, status: 'ALLOWED' as const, reason: 'Valid deploy', verification_latency_ms: 0.5, event_type: 'STANDARD_VERIFICATION' },
      // rotateEncryptionKeys: 1 RBAC BLOCKED => 1 total, 1 blocked
      { username: 'guest_u', requested_function: '/api/rotateEncryptionKeys', calculated_risk: 90, status: 'BLOCKED' as const, reason: 'RBAC unauthorized role', verification_latency_ms: 0.2, event_type: 'RBAC_VIOLATION' },
      // getDashboardMetrics: 3 ALLOWED => latencies [0.2, 0.4, 0.6] -> mean 0.4ms, 0 blocked
      { username: 'cloud_dev', requested_function: '/api/getDashboardMetrics', calculated_risk: 10, status: 'ALLOWED' as const, reason: 'Nominal call', verification_latency_ms: 0.2, event_type: 'STANDARD_VERIFICATION' },
      { username: 'cloud_dev', requested_function: '/api/getDashboardMetrics', calculated_risk: 10, status: 'ALLOWED' as const, reason: 'Nominal call', verification_latency_ms: 0.4, event_type: 'STANDARD_VERIFICATION' },
      { username: 'cloud_dev', requested_function: '/api/getDashboardMetrics', calculated_risk: 10, status: 'ALLOWED' as const, reason: 'Nominal call', verification_latency_ms: 0.6, event_type: 'STANDARD_VERIFICATION' }
    ];
    for (const rec of hmRecords) {
      auditRepository.record(rec);
    }

    const overviewRes: any = await (await originalFetch(`${baseUrl}/api/system/overview`)).json();
    assert.strictEqual(overviewRes.logs.length, 11);
    assert.strictEqual(overviewRes.stats.blockedCount, 6);
    assert.strictEqual(overviewRes.stats.allowedCount, 5);
    const measuredOverviewLatencies = hmRecords
      .map((r) => r.verification_latency_ms)
      .filter((n) => typeof n === 'number' && n > 0);
    const expectedMeanOverviewLat = Number(
      (measuredOverviewLatencies.reduce((a, b) => a + b, 0) / measuredOverviewLatencies.length).toFixed(3)
    );
    assert.strictEqual(overviewRes.stats.avgVerificationLatencyMs, expectedMeanOverviewLat);

    // Check zero-latency fallback removal on an empty ledger
    auditRepository.clear();
    const emptyOverview: any = await (await originalFetch(`${baseUrl}/api/system/overview`)).json();
    assert.strictEqual(emptyOverview.stats.avgVerificationLatencyMs, 0, 'Empty ledger must report 0 latency (no synthetic 0.38ms fallback)');

    // Re-seed exact deterministic rows for UI + model verification
    for (const rec of hmRecords) auditRepository.record(rec);
    const liveOverview: any = await (await originalFetch(`${baseUrl}/api/system/overview`)).json();

    const model = buildHeatmapModel({
      logs: liveOverview.logs,
      axisMode: 'vector',
      intensityBasis: 'composite',
      trafficFilter: 'ALL',
      functionQuery: '',
      maxThreshold: 75
    });

    assert.strictEqual(model.totalEvaluatedLogs, 11);
    assert.strictEqual(model.totalBlockedLogs, 6);
    assert.strictEqual(model.rows.length, 3);

    // Exact ranking order from DB: deployWorkerCode (5 blocked) -> rotateEncryptionKeys (1 blocked) -> getDashboardMetrics (0 blocked)
    assert.strictEqual(model.rows[0].functionName, 'deployWorkerCode');
    assert.strictEqual(model.rows[0].totalHits, 7);
    assert.strictEqual(model.rows[0].blockedHits, 5);
    assert.strictEqual(model.rows[0].allowedHits, 2);
    assert.strictEqual(model.rows[0].peakRisk, 95);
    assert.strictEqual(model.rows[0].blockRatePct, Math.round((5 / 7) * 100)); // 71
    assert.strictEqual(model.rows[0].attackSharePct, Math.round((5 / 6) * 100)); // 83
    assert.strictEqual(model.rows[0].primaryVector, 'Cloud SSRF');

    assert.strictEqual(model.rows[1].functionName, 'rotateEncryptionKeys');
    assert.strictEqual(model.rows[1].blockedHits, 1);
    assert.strictEqual(model.rows[1].blockRatePct, 100);
    assert.strictEqual(model.rows[1].primaryVector, 'RBAC Breach');

    assert.strictEqual(model.rows[2].functionName, 'getDashboardMetrics');
    assert.strictEqual(model.rows[2].blockedHits, 0);
    assert.strictEqual(model.rows[2].allowedHits, 3);
    assert.strictEqual(model.rows[2].avgRisk, 10);
    assert.strictEqual(model.rows[2].blockRatePct, 0);

    // Exact coordinate cell checks
    const ssrfCell = model.cells[0][0]; // y=0 (deployWorkerCode), x=0 (Cloud SSRF)
    assert.strictEqual(ssrfCell.totalHits, 3);
    assert.strictEqual(ssrfCell.blockedHits, 3);
    assert.strictEqual(ssrfCell.maxRisk, 95);
    assert.strictEqual(ssrfCell.avgLatencyMs, 0.5); // (0.4+0.6+0.5)/3
    assert.strictEqual(model.hottestCell?.functionName, 'deployWorkerCode');
    assert.strictEqual(model.hottestCell?.columnLabel, 'Cloud SSRF');

    const nomGetMetricsCell = model.cells[2][6]; // y=2 (getDashboardMetrics), x=6 (Nominal Baseline)
    assert.strictEqual(nomGetMetricsCell.totalHits, 3);
    assert.strictEqual(nomGetMetricsCell.avgLatencyMs, 0.4); // (0.2+0.4+0.6)/3

    // Mount real <ThreatHeatmap /> UI against live overview data and verify exact numbers render
    globalThis.fetch = ((input: any, init?: any) => {
      const u = typeof input === 'string' && input.startsWith('/') ? `${baseUrl}${input}` : input;
      return originalFetch(u, init);
    }) as any;
    setActiveAuthToken(adminToken);

    const hmContainer = doc.createElement('div');
    doc.body.appendChild(hmContainer);
    const hmRoot = createRoot(hmContainer as any);
    await React.act(async () => {
      hmRoot.render(
        React.createElement(
          ThemeProvider,
          null,
          React.createElement(ThreatHeatmap, {
            logs: liveOverview.logs,
            maxThreshold: 75,
            realtimeTelemetry: {
              connectionStatus: 'LIVE_STREAMING',
              lastServerTime: new Date().toISOString(),
              streamEventsCount: 1,
              reconnectAttempts: 0,
              isLive: true
            }
          })
        )
      );
    });
    assert.ok(hmContainer.textContent.includes('1. deployWorkerCode'));
    assert.ok(hmContainer.textContent.includes('5 blk / 7'));
    assert.ok(hmContainer.textContent.includes('71% denied'));
    assert.ok(hmContainer.textContent.includes('2. rotateEncryptionKeys'));
    await React.act(async () => { hmRoot.unmount(); });
    doc.body.removeChild(hmContainer);
    setActiveAuthToken(null);
    console.log('✔ PASS 2 (Heatmap Accuracy): Exact DB-to-overview-to-heatmap coordinate, risk, blockRate, latency & ranking parity verified');

    // =========================================================================
    // CHECKPOINT 3: Concurrent Recovery-Code Safety (Express + Worker)
    // =========================================================================
    const concUser = `ConcFinal_${Date.now()}`;
    const concPass = `ConcPass_${Date.now()}!`;
    userRepository.create({
      username: concUser,
      password: concPass,
      role: 'Developer',
      base_risk_score: 10,
      status: 'APPROVED'
    });

    const loginCh: any = await (await originalFetch(`${baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: concUser, password: concPass })
    })).json();
    assert.strictEqual(loginCh.mfaRequired, true);
    assert.strictEqual(loginCh.enrollmentRequired, true);

    // 5 concurrent enroll-challenge calls must coalesce cleanly to the exact same 8 codes
    const enroll5 = await Promise.all(
      Array.from({ length: 5 }).map(() =>
        originalFetch(`${baseUrl}/api/auth/mfa/enroll-challenge`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfaChallengeId: loginCh.mfaChallengeId, mode: 'recovery_codes' })
        }).then((r) => r.json() as Promise<any>)
      )
    );
    for (const res of enroll5) {
      assert.strictEqual(res.success, true);
      assert.deepStrictEqual(res.backupCodes, enroll5[0].backupCodes, 'Concurrent enroll-challenge calls must coalesce identically');
    }

    // forceRefresh generates a distinct fresh set of 8 codes and invalidates the previous unconfirmed set
    const refreshed: any = await (await originalFetch(`${baseUrl}/api/auth/mfa/enroll-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfaChallengeId: loginCh.mfaChallengeId, mode: 'recovery_codes', forceRefresh: true })
    })).json();
    assert.strictEqual(refreshed.success, true);
    assert.notDeepStrictEqual(refreshed.backupCodes, enroll5[0].backupCodes);

    // Old code from pre-refresh batch must fail without consuming challenge
    const staleTry = await originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfaChallengeId: loginCh.mfaChallengeId, code: enroll5[0].backupCodes[0], method: 'backup_code' })
    });
    assert.strictEqual(staleTry.status, 401);

    // Confirm refreshed code[0] -> completes enrollment and consumes code[0] (remaining=7)
    const confirm0: any = await (await originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfaChallengeId: loginCh.mfaChallengeId, code: refreshed.backupCodes[0], method: 'backup_code' })
    })).json();
    assert.strictEqual(confirm0.success, true);
    assert.strictEqual(confirm0.recoveryCodesRemaining, 7);

    // Replay consumed code[0] -> rejected (401)
    const loginCh2: any = await (await originalFetch(`${baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: concUser, password: concPass })
    })).json();
    assert.strictEqual(loginCh2.enrollmentRequired, false);
    const replayRes = await originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfaChallengeId: loginCh2.mfaChallengeId, code: refreshed.backupCodes[0], method: 'backup_code' })
    });
    assert.strictEqual(replayRes.status, 401, 'Replaying spent recovery code must fail');

    // Race 1: Same code[1] submitted concurrently across two different active challenges
    const loginCh2b: any = await (await originalFetch(`${baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: concUser, password: concPass })
    })).json();
    const [rSameA, rSameB] = await Promise.all([
      originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: loginCh2.mfaChallengeId, code: refreshed.backupCodes[1], method: 'backup_code' })
      }),
      originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: loginCh2b.mfaChallengeId, code: refreshed.backupCodes[1], method: 'backup_code' })
      })
    ]);
    assert.strictEqual([rSameA, rSameB].filter((r) => r.status === 200).length, 1, 'Same recovery code across 2 challenges must succeed strictly once');
    assert.strictEqual(userRepository.findByUsername(concUser)!.mfa_backup_codes!.length, 6);

    // Race 2: Same challenge submitted concurrently with 2 DIFFERENT valid codes (code[2] & code[3]) -> strictly 1 succeeds, other code remains valid!
    const loginCh3: any = await (await originalFetch(`${baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: concUser, password: concPass })
    })).json();
    const [rDiffA, rDiffB] = await Promise.all([
      originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: loginCh3.mfaChallengeId, code: refreshed.backupCodes[2], method: 'backup_code' })
      }).then(async (r) => ({ status: r.status, code: refreshed.backupCodes[2], body: await r.json() as any })),
      originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: loginCh3.mfaChallengeId, code: refreshed.backupCodes[3], method: 'backup_code' })
      }).then(async (r) => ({ status: r.status, code: refreshed.backupCodes[3], body: await r.json() as any }))
    ]);
    assert.strictEqual([rDiffA, rDiffB].filter((r) => r.status === 200).length, 1, 'Same challenge raced with 2 distinct codes must accept strictly 1');
    assert.strictEqual(userRepository.findByUsername(concUser)!.mfa_backup_codes!.length, 5, 'Unwon distinct recovery code must NOT be consumed');

    const losingCode = rDiffA.status === 200 ? rDiffB.code : rDiffA.code;
    const loginCh4: any = await (await originalFetch(`${baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: concUser, password: concPass })
    })).json();
    const retryLoserCode = await originalFetch(`${baseUrl}/api/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfaChallengeId: loginCh4.mfaChallengeId, code: losingCode, method: 'backup_code' })
    });
    assert.strictEqual(retryLoserCode.status, 200, 'Code from rejected concurrent attempt on already-consumed challenge must remain usable');
    assert.strictEqual(userRepository.findByUsername(concUser)!.mfa_backup_codes!.length, 4);

    console.log('✔ PASS 3 (Concurrent Recovery Safety): Express coalescing, forceRefresh, replay protection, dual-challenge race & same-challenge distinct-code race verified');

    // =========================================================================
    // CHECKPOINT 4: SSE Reliability (Disconnects, Reconnects, Dedup & Polling Fallback)
    // =========================================================================
    // 4A. Real HTTP stream handshake latestAuditId + disconnect + reconnect
    const sseAbort1 = new AbortController();
    const stream1 = await originalFetch(`${baseUrl}/api/v1/realtime/stream`, { signal: sseAbort1.signal });
    const reader1 = stream1.body!.getReader();
    const chunk1 = await reader1.read();
    const firstFrame = new TextDecoder().decode(chunk1.value);
    const connectedLine = firstFrame.split('\n').find((l) => l.startsWith('data:'))!;
    const connectedJson = JSON.parse(connectedLine.slice(5).trim());
    assert.strictEqual(connectedJson.type, 'CONNECTED');
    assert.ok(typeof connectedJson.latestAuditId === 'number' && connectedJson.latestAuditId > 0, 'SSE handshake must include latestAuditId');
    sseAbort1.abort();

    // 4B. Hook disconnect -> POLLING_FALLBACK delivers missed event from /api/system/overview -> reconnect -> deduplicates replay
    let pollSimulatedLog: any = null;
    globalThis.fetch = (async (input: any, init?: any) => {
      const u = typeof input === 'string' && input.startsWith('/') ? `${baseUrl}${input}` : String(input);
      if (u.endsWith('/api/system/overview') && pollSimulatedLog) {
        return new Response(JSON.stringify({ logs: [pollSimulatedLog] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      return originalFetch(u, init);
    }) as any;

    const fakeSources: any[] = [];
    class ControlledEventSource {
      url: string;
      onopen: (() => void) | null = null;
      onmessage: ((ev: { data: string }) => void) | null = null;
      onerror: ((err?: any) => void) | null = null;
      closed = false;
      constructor(u: string) {
        this.url = u;
        fakeSources.push(this);
      }
      close() { this.closed = true; }
    }
    (globalThis as any).EventSource = ControlledEventSource;

    const sseHookDiv = doc.createElement('div');
    doc.body.appendChild(sseHookDiv);
    let hookState: any = null;
    const hookLogs: any[] = [];
    const Probe = () => {
      hookState = useRealtimeMonitor({
        pollingIntervalMs: 80,
        onNewLog: (l) => hookLogs.push(l)
      });
      return React.createElement('span', null, hookState.connectionStatus);
    };
    const hookRoot = createRoot(sseHookDiv as any);
    await React.act(async () => { hookRoot.render(React.createElement(Probe)); });

    // Open + CONNECTED handshake establishes cursor at id=1000
    await React.act(async () => {
      fakeSources[0].onopen?.();
      fakeSources[0].onmessage?.({
        data: JSON.stringify({ type: 'CONNECTED', latestAuditId: 1000, timestamp: new Date().toISOString() })
      });
    });
    assert.strictEqual(hookState.connectionStatus, 'LIVE_STREAMING');

    // Duplicate SSE event id=1001 delivered once
    const sseEv1001 = JSON.stringify({
      type: 'NEW_INVOCATION',
      timestamp: '2026-11-23T10:00:00Z',
      data: { id: 1001, timestamp: '2026-11-23T10:00:00Z', requested_function: '/api/sse_1001', username: 'u', calculated_risk: 10, status: 'ALLOWED', reason: 'ok' }
    });
    await React.act(async () => {
      fakeSources[0].onmessage?.({ data: sseEv1001 });
      fakeSources[0].onmessage?.({ data: sseEv1001 });
    });
    assert.strictEqual(hookLogs.length, 1);

    // Outage: id=1002 occurs while SSE is down -> POLLING_FALLBACK retrieves it via /api/system/overview
    pollSimulatedLog = {
      id: 1002,
      timestamp: '2026-11-23T10:01:00Z',
      username: 'outage_actor',
      requested_function: '/api/deployWorkerCode',
      calculated_risk: 95,
      status: 'BLOCKED',
      reason: 'Captured during POLLING_FALLBACK'
    };
    await React.act(async () => {
      fakeSources[0].onerror?.(new Error('network drop'));
      await new Promise((r) => setTimeout(r, 150));
    });
    assert.strictEqual(hookState.connectionStatus, 'POLLING_FALLBACK');
    assert.strictEqual(hookLogs.length, 2, 'POLLING_FALLBACK must deliver missed event #1002');
    assert.strictEqual(hookLogs[1].id, 1002);

    // Wait for reconnect -> open #2 -> even if SSE replays #1002, it must be deduplicated
    await React.act(async () => {
      await new Promise((r) => setTimeout(r, 3100));
    });
    assert.strictEqual(fakeSources.length, 2);
    await React.act(async () => {
      fakeSources[1].onopen?.();
      fakeSources[1].onmessage?.({
        data: JSON.stringify({ type: 'NEW_INVOCATION', timestamp: pollSimulatedLog.timestamp, data: pollSimulatedLog })
      });
    });
    assert.strictEqual(hookState.connectionStatus, 'LIVE_STREAMING');
    assert.strictEqual(hookLogs.length, 2, 'Event delivered during POLLING_FALLBACK must not duplicate on SSE reconnect');

    await React.act(async () => { hookRoot.unmount(); });
    doc.body.removeChild(sseHookDiv);
    console.log('✔ PASS 4 (SSE Reliability): Handshake cursor, disconnect -> POLLING_FALLBACK delivery, reconnect & cross-mode deduplication verified');

    // =========================================================================
    // CHECKPOINT 5: Cloudflare Worker & Persistent Local File-Backed D1
    // =========================================================================
    const bootstrapPwd = `BootAdmin_${Date.now()}!`;
    const workerEnvBase = {
      ENVIRONMENT: 'development',
      ZERO_TRUST_ORIGIN: 'https://serverless-securityverification.ai.studio',
      JWT_SECRET: 'worker_final_audit_jwt_secret_minimum_32_chars_2026',
      INITIAL_ADMIN_PASSWORD: bootstrapPwd
    };
    const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

    const workerDbA = new PersistentSecurityDatabase(tmpWorkerDbPath);
    let workerAdminJwt = '';
    {
      // Simulate fresh Cloudflare D1 state after migrations/0001-0004 (before Node bootstrap)
      workerDbA.prepare("UPDATE users SET password_hash = '!BOOTSTRAP_REQUIRED!' WHERE username = 'secops_admin'").run();
      const envA = { ...workerEnvBase, DB: createAsyncD1Adapter(workerDbA) };

      // 5A. Verify Worker INITIAL_ADMIN_PASSWORD bootstrap on !BOOTSTRAP_REQUIRED! secops_admin
      const wLogin: any = await (await worker.fetch(new Request('http://localhost/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: bootstrapPwd })
      }), envA, ctx)).json();
      assert.strictEqual(wLogin.mfaRequired, true, 'Worker INITIAL_ADMIN_PASSWORD bootstrap must authenticate secops_admin');

      const adminRowA: any = workerDbA.prepare("SELECT mfa_secret FROM users WHERE username = 'secops_admin'").first();
      const { generateTotpToken } = await import('../src/utils/mfa.ts');
      const totpCode = generateTotpToken(adminRowA.mfa_secret);
      const wMfa: any = await (await worker.fetch(new Request('http://localhost/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: wLogin.mfaChallengeId, code: totpCode, method: 'authenticator' })
      }), envA, ctx)).json();
      assert.strictEqual(wMfa.success, true);
      workerAdminJwt = wMfa.token;

      // Write 225 chained invocations through Worker D1 pipeline
      for (let i = 0; i < 225; i++) {
        const invRes = await worker.fetch(new Request('http://localhost/api/v1/verify/invoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${workerAdminJwt}` },
          body: JSON.stringify({ functionName: 'getDashboardMetrics', payload: { seq: i } })
        }), envA, ctx);
        assert.strictEqual(invRes.status, 200);
      }

      // Overview returns up to 200 events (consistent with Express)
      const wOverview: any = await (await worker.fetch(new Request('http://localhost/api/system/overview'), envA, ctx)).json();
      assert.strictEqual(wOverview.logs.length, 200, 'Worker /api/system/overview must return latest 200 events');

      // Full-ledger verify-chain passes with genesis + HMAC anchor across >200 rows
      const wChainClean: any = await (await worker.fetch(new Request('http://localhost/api/v1/audit/verify-chain', {
        headers: { Authorization: `Bearer ${workerAdminJwt}` }
      }), envA, ctx)).json();
      assert.strictEqual(wChainClean.chainIntact, true);
      assert.strictEqual(wChainClean.genesisVerified, true);
      assert.strictEqual(wChainClean.anchorPresent, true);
      assert.strictEqual(wChainClean.anchorVerified, true);
      assert.ok(wChainClean.totalChecked >= 225);

      workerDbA.close();
    }

    // 5B. Re-open file-backed Worker DB, tamper historical row #3 (>200 back), verify Worker detects it!
    const workerDbB = new PersistentSecurityDatabase(tmpWorkerDbPath);
    try {
      const envB = { ...workerEnvBase, DB: createAsyncD1Adapter(workerDbB) };

      // Verify unauthenticated request to /api/v1/audit/verify-chain fails closed (401)
      const unauthChain = await worker.fetch(new Request('http://localhost/api/v1/audit/verify-chain'), envB, ctx);
      assert.strictEqual(unauthChain.status, 401);

      // Tamper row #3 (>200 rows back)
      const allW = workerDbB.prepare('SELECT id FROM audit_events ORDER BY id ASC').all<any>().results;
      const targetOldId = allW[2].id;
      workerDbB.prepare("UPDATE audit_events SET reason = 'TamperedWorkerOldRow' WHERE id = ?").bind(targetOldId).run();

      const wChainTampered: any = await (await worker.fetch(new Request('http://localhost/api/v1/audit/verify-chain', {
        headers: { Authorization: `Bearer ${workerAdminJwt}` }
      }), envB, ctx)).json();
      assert.strictEqual(wChainTampered.chainIntact, false, 'Worker /api/v1/audit/verify-chain must detect tampering >200 rows back');
      assert.ok(wChainTampered.brokenLinks.some((b: any) => b.id === targetOldId && b.reason === 'HASH_MISMATCH'));
    } finally {
      workerDbB.close();
    }

    console.log('✔ PASS 5 (Worker + File-Backed D1): Optional admin bootstrap, 200-row overview, >225-row Worker /api/v1/audit/verify-chain & historical tamper detection passed (Remote Cloudflare deployment requires wrangler + credentials unavailable in offline sandbox)');

    // =========================================================================
    // CHECKPOINT 6: Anchor Governance, Key Rotation, Concurrent Batch Writes,
    // Legacy Baseline Sealing & ThreatHeatmap Governance UI
    // =========================================================================
    // 6A. Concurrent Audit Writes on Express & Worker (using D1 adapter batch())
    auditRepository.clear();
    const devUser = userRepository.findByUsername('cloud_dev')!;
    const devToken = signJwt({
      sub: devUser.id,
      username: devUser.username,
      role: 'Developer',
      jti: `jti_dev_${crypto.randomBytes(4).toString('hex')}`,
      expiresInSeconds: 3600
    });
    sessionRepository.createSession({
      userId: devUser.id,
      username: devUser.username,
      role: 'Developer',
      token: devToken,
      expiresInSeconds: 3600,
      ipAddress: '127.0.0.1'
    });

    await Promise.all(
      Array.from({ length: 12 }).map((_, idx) =>
        originalFetch(`${baseUrl}/api/v1/verify/invoke`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
          body: JSON.stringify({ functionName: 'getDashboardMetrics', payload: { concurrentSeq: idx } })
        }).then((r) => assert.strictEqual(r.status, 200))
      )
    );
    const expressAnchorAfterConc = db.prepare('SELECT * FROM audit_chain_anchor WHERE id = 1').first<any>();
    const expressConcChain = auditRepository.verifyIntegrityChain();
    assert.strictEqual(expressConcChain.chainIntact, true, 'Express concurrent writes must maintain intact SHA-256 chain');
    assert.strictEqual(expressConcChain.anchorVerified, true);
    assert.strictEqual(expressAnchorAfterConc.record_count, expressConcChain.totalInLedger);

    // 6B. Express Key Rotation RBAC (Developer 403 -> Admin 200) & Non-Leakage Check
    const customSecretExpress = `exp_hmac_secret_${crypto.randomBytes(12).toString('hex')}`;
    const devRotateRes = await originalFetch(`${baseUrl}/api/v1/audit/rotate-anchor-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${devToken}` },
      body: JSON.stringify({ newKeyId: 'anchor-dev-attempt', newSecret: customSecretExpress, reason: 'Unauthorized attempt' })
    });
    assert.strictEqual(devRotateRes.status, 403, 'Developer must be blocked (403) from rotating audit anchor key');

    const rotateExpressRes = await originalFetch(`${baseUrl}/api/v1/audit/rotate-anchor-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ newKeyId: 'anchor-v2-exp', newSecret: customSecretExpress, reason: 'Scheduled rotation' })
    });
    assert.strictEqual(rotateExpressRes.status, 200);
    const rotateExpressJson: any = await rotateExpressRes.json();
    assert.strictEqual(rotateExpressJson.keyId, 'anchor-v2-exp');
    assert.strictEqual(rotateExpressJson.anchor.activeKeyId, 'anchor-v2-exp');
    assert.strictEqual(rotateExpressJson.verification.chainIntact, true);

    const anchorStatusExpressRes: any = await (await originalFetch(`${baseUrl}/api/v1/audit/anchor-status`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    })).json();
    assert.strictEqual(anchorStatusExpressRes.anchor.activeKeyId, 'anchor-v2-exp');

    const serializeCheck = JSON.stringify({ rotateExpressJson, anchorStatusExpressRes });
    assert.ok(!serializeCheck.includes(customSecretExpress), 'HMAC anchor secret must NEVER appear in API responses');

    // 6C. Express Legacy Baseline Sealing (Preserves Historical Rows, Never Marks Legacy Valid, Detects Legacy Snapshot Tampering)
    const preTamperRows = db.prepare('SELECT id FROM audit_events ORDER BY id ASC').all<any>().results;
    const legacyTargetId = preTamperRows[1].id;
    db.prepare('UPDATE audit_events SET reason = ? WHERE id = ?').bind('Historical pre-upgrade mismatch', legacyTargetId).run();

    const preBaselineVerify: any = await (await originalFetch(`${baseUrl}/api/v1/audit/verify-chain`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    })).json();
    assert.strictEqual(preBaselineVerify.chainIntact, false);
    assert.ok(preBaselineVerify.suggestedLegacyCutoffMaxId >= legacyTargetId);

    const baselineExpressRes = await originalFetch(`${baseUrl}/api/v1/audit/baseline-legacy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({
        cutoffMaxId: legacyTargetId,
        epochLabel: 'legacy-epoch-test',
        reason: 'Seal corrupted pre-upgrade history without altering historical records'
      })
    });
    assert.strictEqual(baselineExpressRes.status, 200);
    const baselineExpressJson: any = await baselineExpressRes.json();
    assert.strictEqual(baselineExpressJson.verification.verificationStatus, 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY');
    assert.strictEqual(baselineExpressJson.verification.fullLedgerVerified, false, 'Legacy baseline must NEVER claim full-ledger validity');
    assert.strictEqual(baselineExpressJson.verification.chainIntact, false, 'Legacy baseline must NEVER set chainIntact=true when legacy history exists');
    assert.strictEqual(baselineExpressJson.verification.verifiedEpochIntact, true);
    assert.strictEqual(baselineExpressJson.verification.legacySnapshotVerified, true);
    assert.ok(baselineExpressJson.verification.legacyRecordsCount >= 2);
    // Verify historical tampered row was preserved verbatim
    const preservedLegacyRow = db.prepare('SELECT reason FROM audit_events WHERE id = ?').bind(legacyTargetId).first<any>();
    assert.strictEqual(preservedLegacyRow.reason, 'Historical pre-upgrade mismatch');

    // UI Check: <ThreatHeatmap /> distinguishes VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY vs SHA-256 Chain Verified Intact & renders Admin governance controls
    globalThis.fetch = ((input: any, init?: any) => {
      const u = typeof input === 'string' && input.startsWith('/') ? `${baseUrl}${input}` : String(input);
      return originalFetch(u, init);
    }) as any;
    const liveOverviewAfterBaseline: any = await (await originalFetch(`${baseUrl}/api/system/overview`)).json();

    // Non-admin role must NOT render #audit-anchor-governance
    setActiveAuthToken(devToken);
    const devHmDiv = doc.createElement('div');
    doc.body.appendChild(devHmDiv);
    const devHmRoot = createRoot(devHmDiv as any);
    await React.act(async () => {
      devHmRoot.render(
        React.createElement(
          ThemeProvider,
          null,
          React.createElement(ThreatHeatmap, {
            logs: liveOverviewAfterBaseline.logs,
            userRole: 'Developer',
            maxThreshold: 75
          })
        )
      );
    });
    assert.strictEqual(devHmDiv.querySelector('#audit-anchor-governance'), null, 'Non-admin role must not see audit anchor governance panel');
    await React.act(async () => { devHmRoot.unmount(); });
    doc.body.removeChild(devHmDiv);

    // Admin role renders #audit-anchor-governance, toggles #btn-seal-legacy-baseline / #btn-rotate-anchor-key, and verifies epoch banner
    setActiveAuthToken(adminToken);
    const adminHmDiv = doc.createElement('div');
    doc.body.appendChild(adminHmDiv);
    const adminHmRoot = createRoot(adminHmDiv as any);
    await React.act(async () => {
      adminHmRoot.render(
        React.createElement(
          ThemeProvider,
          null,
          React.createElement(ThreatHeatmap, {
            logs: liveOverviewAfterBaseline.logs,
            userRole: 'Admin',
            maxThreshold: 75
          })
        )
      );
      await new Promise((r) => setTimeout(r, 40));
    });
    assert.ok(adminHmDiv.querySelector('#audit-anchor-governance'), 'Admin must see #audit-anchor-governance');
    const toggleGovBtn = adminHmDiv.querySelector('#btn-toggle-audit-governance');
    assert.ok(toggleGovBtn);
    await React.act(async () => { toggleGovBtn!.click(); });
    assert.ok(adminHmDiv.querySelector('#btn-seal-legacy-baseline'), 'Expanded governance must render #btn-seal-legacy-baseline');
    assert.ok(adminHmDiv.querySelector('#btn-rotate-anchor-key'), 'Expanded governance must render #btn-rotate-anchor-key');

    const verifyBtn = adminHmDiv.querySelector('#btn-verify-audit-chain');
    assert.ok(verifyBtn);
    await React.act(async () => {
      verifyBtn!.click();
      await new Promise((r) => setTimeout(r, 50));
    });
    const bannerLegacy = adminHmDiv.querySelector('#audit-chain-verify-result');
    assert.ok(bannerLegacy, 'Clicking #btn-verify-audit-chain must render #audit-chain-verify-result');
    assert.ok(
      bannerLegacy!.textContent.includes('Modern Epoch Verified') && !bannerLegacy!.textContent.includes('SHA-256 Chain Verified Intact'),
      'Legacy epoch UI banner must explicitly distinguish modern verified epoch from full-ledger verification'
    );

    // Tamper sealed legacy row -> Express verify-chain must detect LEGACY_SNAPSHOT_TAMPERED
    db.prepare('UPDATE audit_events SET reason = ? WHERE id = ?').bind('Modified sealed legacy record', legacyTargetId).run();
    const afterSealedTamper: any = await (await originalFetch(`${baseUrl}/api/v1/audit/verify-chain`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    })).json();
    assert.strictEqual(afterSealedTamper.verificationStatus, 'LEGACY_SNAPSHOT_TAMPERED');
    assert.strictEqual(afterSealedTamper.legacySnapshotVerified, false);

    // Verify clean chain still renders 'SHA-256 Chain Verified Intact'
    auditRepository.clear();
    auditRepository.record({
      username: 'secops_admin',
      requested_function: '/api/getDashboardMetrics',
      calculated_risk: 10,
      status: 'ALLOWED',
      reason: 'Fresh post-audit baseline',
      verification_latency_ms: 0.2,
      event_type: 'STANDARD_VERIFICATION'
    });
    const verifyBtn2 = adminHmDiv.querySelector('#btn-verify-audit-chain');
    assert.ok(verifyBtn2);
    await React.act(async () => {
      verifyBtn2!.click();
      await new Promise((r) => setTimeout(r, 120));
    });
    const bannerClean = adminHmDiv.querySelector('#audit-chain-verify-result');
    assert.ok(
      bannerClean!.textContent.includes('SHA-256 Chain Verified Intact'),
      `Expected clean chain banner, got: ${bannerClean?.textContent}`
    );

    await React.act(async () => { adminHmRoot.unmount(); });
    doc.body.removeChild(adminHmDiv);
    setActiveAuthToken(null);

    // 6D. Worker Governance Parity with DB.batch() (Concurrent Batch Writes + Key Rotation + Legacy Baseline + Sealed Tamper)
    const workerGovDb = new PersistentSecurityDatabase(tmpWorkerGovDbPath);
    try {
      workerGovDb.prepare("UPDATE users SET password_hash = '!BOOTSTRAP_REQUIRED!' WHERE username = 'secops_admin'").run();
      const envGov = {
        ...workerEnvBase,
        AUDIT_ANCHOR_KEY: `worker_env_anchor_${crypto.randomBytes(12).toString('hex')}`,
        DB: createAsyncD1Adapter(workerGovDb)
      };

      const wGovLogin: any = await (await worker.fetch(new Request('http://localhost/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: bootstrapPwd })
      }), envGov, ctx)).json();
      assert.strictEqual(wGovLogin.mfaRequired, true);
      const govAdminRow: any = workerGovDb.prepare("SELECT mfa_secret FROM users WHERE username = 'secops_admin'").first();
      const { generateTotpToken } = await import('../src/utils/mfa.ts');
      const govTotp = generateTotpToken(govAdminRow.mfa_secret);
      const wGovMfa: any = await (await worker.fetch(new Request('http://localhost/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: wGovLogin.mfaChallengeId, code: govTotp, method: 'authenticator' })
      }), envGov, ctx)).json();
      assert.strictEqual(wGovMfa.success, true);
      const govAdminToken = wGovMfa.token;

      // Concurrent Worker invokes exercising DB.batch()
      const wConcResponses = await Promise.all(
        Array.from({ length: 10 }).map((_, idx) =>
          worker.fetch(new Request('http://localhost/api/v1/verify/invoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${govAdminToken}` },
            body: JSON.stringify({ functionName: 'getDashboardMetrics', payload: { wConcSeq: idx } })
          }), envGov, ctx)
        )
      );
      for (const r of wConcResponses) assert.strictEqual(r.status, 200);

      const wAnchorAfterConc = workerGovDb.prepare('SELECT * FROM audit_chain_anchor WHERE id = 1').first<any>();
      const wCountAfterConc = workerGovDb.prepare('SELECT COUNT(*) as c FROM audit_events').first<any>();
      assert.strictEqual(wAnchorAfterConc.record_count, wCountAfterConc.c, 'Worker DB.batch anchor count must match audit_events count');

      // Worker key rotation + Developer RBAC 403
      const { hashPassword } = await import('../server/utils/crypto.ts');
      const wDevPwd = `WDevPwd_${Date.now()}!`;
      const wDevHash = hashPassword(wDevPwd);
      workerGovDb
        .prepare("UPDATE users SET password_salt = ?, password_hash = ?, status = 'APPROVED', mfa_enrolled = 1 WHERE username = 'cloud_dev'")
        .bind(wDevHash.salt, wDevHash.hash)
        .run();
      const wDevLogin: any = await (await worker.fetch(new Request('http://localhost/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'cloud_dev', password: wDevPwd })
      }), envGov, ctx)).json();
      assert.strictEqual(wDevLogin.mfaRequired, true);
      const wDevRow = workerGovDb.prepare("SELECT mfa_secret FROM users WHERE username = 'cloud_dev'").first<any>();
      const wDevTotp = generateTotpToken(wDevRow.mfa_secret);
      const wDevMfa: any = await (await worker.fetch(new Request('http://localhost/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: wDevLogin.mfaChallengeId, code: wDevTotp, method: 'authenticator' })
      }), envGov, ctx)).json();
      assert.strictEqual(wDevMfa.success, true);
      const workerDevToken = wDevMfa.token;

      const wDevRotate = await worker.fetch(new Request('http://localhost/api/v1/audit/rotate-anchor-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${workerDevToken}` },
        body: JSON.stringify({ newKeyId: 'w-dev-nope' })
      }), envGov, ctx);
      assert.strictEqual(wDevRotate.status, 403);

      const wCustomSecret = `worker_hmac_rot_${crypto.randomBytes(12).toString('hex')}`;
      const wAdminRotateRes = await worker.fetch(new Request('http://localhost/api/v1/audit/rotate-anchor-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${govAdminToken}` },
        body: JSON.stringify({ newKeyId: 'anchor-w-v2', newSecret: wCustomSecret, reason: 'Worker key rotation audit' })
      }), envGov, ctx);
      assert.strictEqual(wAdminRotateRes.status, 200);
      const wAdminRotateJson: any = await wAdminRotateRes.json();
      assert.strictEqual(wAdminRotateJson.keyId, 'anchor-w-v2');
      assert.strictEqual(wAdminRotateJson.verification.chainIntact, true);
      assert.ok(!JSON.stringify(wAdminRotateJson).includes(wCustomSecret), 'Worker rotation response must never expose HMAC secret');

      // Worker legacy baseline sealing & post-seal tamper detection
      const wRows = workerGovDb.prepare('SELECT id FROM audit_events ORDER BY id ASC').all<any>().results;
      const wLegacyId = wRows[1].id;
      workerGovDb.prepare('UPDATE audit_events SET reason = ? WHERE id = ?').bind('Worker legacy corrupted row', wLegacyId).run();

      const wBaselineRes = await worker.fetch(new Request('http://localhost/api/v1/audit/baseline-legacy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${govAdminToken}` },
        body: JSON.stringify({ cutoffMaxId: wLegacyId, epochLabel: 'worker-legacy-epoch', reason: 'Archive worker legacy records' })
      }), envGov, ctx);
      assert.strictEqual(wBaselineRes.status, 200);
      const wBaselineJson: any = await wBaselineRes.json();
      assert.strictEqual(wBaselineJson.verification.verificationStatus, 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY');
      assert.strictEqual(wBaselineJson.verification.fullLedgerVerified, false);
      assert.strictEqual(wBaselineJson.verification.chainIntact, false);
      assert.strictEqual(wBaselineJson.verification.legacySnapshotVerified, true);

      workerGovDb.prepare('UPDATE audit_events SET reason = ? WHERE id = ?').bind('Post-seal worker tamper', wLegacyId).run();
      const wVerifyTampered: any = await (await worker.fetch(new Request('http://localhost/api/v1/audit/verify-chain', {
        headers: { Authorization: `Bearer ${govAdminToken}` }
      }), envGov, ctx)).json();
      assert.strictEqual(wVerifyTampered.verificationStatus, 'LEGACY_SNAPSHOT_TAMPERED');
      assert.strictEqual(wVerifyTampered.legacySnapshotVerified, false);
    } finally {
      workerGovDb.close();
    }

    console.log('✔ PASS 6 (Anchor Governance & Legacy Baseline): Express + Worker D1 batch concurrent writes, key rotation RBAC/non-leakage, legacy epoch preservation, sealed-tamper detection & UI distinction verified');
    console.log('\nALL 6 PRE-FINALIZATION VERIFICATION CHECKPOINTS PASSED (6/6)\n');
  } finally {
    globalThis.fetch = originalFetch;
    if (originalEventSource) (globalThis as any).EventSource = originalEventSource;
    else delete (globalThis as any).EventSource;

    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
    for (const basePath of [tmpExpressDbPath, tmpWorkerDbPath, tmpWorkerGovDbPath]) {
      for (const ext of ['', '-wal', '-shm']) {
        const f = `${basePath}${ext}`;
        if (fs.existsSync(f)) {
          try { fs.unlinkSync(f); } catch { /* ignore */ }
        }
      }
    }
  }
}

runTests().catch((err) => {
  console.error('❌ Pre-Finalization Verification Suite Failed:', err);
  process.exit(1);
});
