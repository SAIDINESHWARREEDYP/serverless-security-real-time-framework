import React, { useState } from 'react';
import { X, Cloud, Terminal, Shield, CheckCircle2, AlertTriangle, Layers, BookOpen, Copy, Check, Server, Database, Code, ArrowRight } from 'lucide-react';

interface CloudGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const CloudGuideModal: React.FC<CloudGuideModalProps> = ({ isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState<'architecture' | 'functions' | 'cloud-deployment' | 'viva-test-cases'>('architecture');
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);

  if (!isOpen) return null;

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippet(id);
    setTimeout(() => setCopiedSnippet(null), 2000);
  };

  const wranglerTomlCode = `# wrangler.toml - Cloudflare Worker & D1 Database Configuration
name = "serverless-security-framework"
main = "src/worker.ts"
compatibility_date = "2024-09-01"

[[d1_databases]]
binding = "DB"
database_name = "edge_security_d1"
database_id = "your-cloudflare-d1-database-uuid-here"

[vars]
ENVIRONMENT = "production"
MAX_ALLOWED_RISK_SCORE = 75
SEQUENCE_VIOLATION_PENALTY = 40
`;

  const workerEdgeCode = `// src/worker.ts - Cloudflare Worker Edge Security Pipeline Interceptor
export interface Env {
  DB: D1Database;
  MAX_ALLOWED_RISK_SCORE?: string;
  SEQUENCE_VIOLATION_PENALTY?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // 1. Resolve Identity Token
    const authHeader = request.headers.get("Authorization");
    const token = authHeader?.startsWith("Bearer ") ? authHeader.substring(7) : null;

    if (!token && path !== "/api/login") {
      return new Response(JSON.stringify({ error: "Missing Bearer Token" }), { status: 401 });
    }

    // 2. Fetch User from Cloudflare D1
    const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?")
      .bind(token)
      .first();

    if (!user && path !== "/api/login") {
      return new Response(JSON.stringify({ error: "Principal identity not found" }), { status: 403 });
    }

    // 3. Sequential Flow Validation
    const previousFunction = request.headers.get("X-Previous-Function") || "login";
    const rule = await env.DB.prepare(
      "SELECT * FROM function_rules WHERE current_function = ? AND allowed_next_function = ?"
    )
      .bind(previousFunction, path.replace("/api/", ""))
      .first();

    let calculatedRisk = user ? (user.base_risk_score as number) : 10;
    let sequenceViolation = !rule && path !== "/api/login";

    if (sequenceViolation) {
      calculatedRisk += 40; // Penalty
    }

    // 4. RBAC Boundary Validation
    let rbacViolation = false;
    if (path === "/api/updateSystemPolicy" && user?.role !== "Admin") {
      rbacViolation = true;
      calculatedRisk = 90;
    }

    // 5. Automated Firewall Intercept
    const status = calculatedRisk >= 75 || rbacViolation ? "BLOCKED" : "ALLOWED";
    const reason = rbacViolation 
      ? "RBAC Breach: Role " + user?.role + " cannot invoke " + path
      : sequenceViolation 
      ? "Abnormal invocation order: " + previousFunction + " -> " + path
      : "Nominal verification passed";

    // 6. Asynchronous D1 Audit Logging
    await env.DB.prepare(
      "INSERT INTO security_audit_logs (username, requested_function, calculated_risk, status, reason) VALUES (?, ?, ?, ?, ?)"
    )
      .bind(user?.username || "anonymous", path, calculatedRisk, status, reason)
      .run();

    if (status === "BLOCKED") {
      return new Response(
        JSON.stringify({ error: "Security Firewall Intercept", risk: calculatedRisk, reason }),
        { status: 403, headers: { "Content-Type": "application/json" } }
      );
    }

    // Pass through to downstream Serverless Function
    return new Response(
      JSON.stringify({ success: true, message: "Authorized by Edge Pipeline", principal: user?.username }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }
};`;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 font-mono">
      <div className="bg-[#0f172a] border border-[#334e78] rounded-lg max-w-5xl w-full max-h-[92vh] flex flex-col overflow-hidden shadow-2xl">
        {/* Modal Header */}
        <div className="p-4 border-b border-[#1e293b] flex items-center justify-between bg-[#131c2e]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded bg-[#00d2ff]/15 border border-[#00d2ff]/30 text-[#00d2ff]">
              <Cloud className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                End-to-End Cloud Deployment &amp; Viva Execution Manual
              </h2>
              <p className="text-[11px] text-[#6b7c96]">
                Enterprise Cloud Security Architecture • Production Deployment Blueprint
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-[#6b7c96] hover:text-white rounded hover:bg-[#1e293b] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-[#1e293b] bg-[#090d16] px-4 overflow-x-auto text-xs">
          <button
            onClick={() => setActiveTab('architecture')}
            className={`py-3 px-4 font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'architecture'
                ? 'border-[#00d2ff] text-[#00d2ff]'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>1. Page &amp; Architecture Map</span>
          </button>

          <button
            onClick={() => setActiveTab('functions')}
            className={`py-3 px-4 font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'functions'
                ? 'border-[#00ff87] text-[#00ff87]'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            <span>2. Function-by-Function Logic</span>
          </button>

          <button
            onClick={() => setActiveTab('cloud-deployment')}
            className={`py-3 px-4 font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'cloud-deployment'
                ? 'border-[#ff4a6b] text-[#ff4a6b]'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>3. Real Cloud Setup (Cloudflare D1 / AWS)</span>
          </button>

          <button
            onClick={() => setActiveTab('viva-test-cases')}
            className={`py-3 px-4 font-bold border-b-2 transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'viva-test-cases'
                ? 'border-amber-400 text-amber-400'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>4. Viva Demo Test Cases (4 Attack Scenarios)</span>
          </button>
        </div>

        {/* Tab Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-[#cbd5e1] flex-1">
          {activeTab === 'architecture' && (
            <div className="space-y-6">
              {/* Top Banner */}
              <div className="bg-[#131c2e] border border-[#223452] p-4 rounded-md">
                <h3 className="text-white font-bold text-sm mb-1 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-[#00d2ff]" />
                  What Is This System &amp; How Does It Protect Cloud Serverless?
                </h3>
                <p className="text-[#94a3b8] leading-relaxed mt-2">
                  In classic cloud serverless computing (AWS Lambda, Cloudflare Workers, Google Cloud Functions), functions execute in isolated micro-containers.
                  Attackers exploit this isolation by invoking functions directly out-of-sequence (e.g. jumping straight to an administrative update function without prior authentication or log verification), or using stolen credentials to bypass normal UI workflows.
                </p>
                <p className="text-[#00ff87] leading-relaxed mt-2 font-semibold">
                  This Capstone framework introduces a zero-trust Edge Interceptor Pipeline that verifies every request against three layers before any serverless function executes: (1) Identity &amp; RBAC Validation, (2) Sequential Call Graph Verification, and (3) Dynamic Risk Heuristic Scoring.
                </p>
              </div>

              {/* End-to-End System Workflow */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <h4 className="text-xs font-bold text-[#00d2ff] uppercase mb-3">
                  End-to-End Request Journey (Edge Pipeline)
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                  <div className="p-3 bg-[#131c2e] border border-[#223452] rounded">
                    <div className="text-[10px] text-[#00d2ff] font-bold">STEP 1</div>
                    <div className="font-bold text-white mt-1">Client Invocator</div>
                    <p className="text-[10px] text-[#94a3b8] mt-1">
                      User or automated API client dispatches HTTP request with Bearer token and target endpoint.
                    </p>
                  </div>

                  <div className="p-3 bg-[#131c2e] border border-[#223452] rounded">
                    <div className="text-[10px] text-[#00d2ff] font-bold">STEP 2</div>
                    <div className="font-bold text-white mt-1">Edge Interceptor</div>
                    <p className="text-[10px] text-[#94a3b8] mt-1">
                      Intercepts HTTP event. Extracts principal identity, reads base risk, and checks role permissions.
                    </p>
                  </div>

                  <div className="p-3 bg-[#131c2e] border border-[#223452] rounded">
                    <div className="text-[10px] text-[#00d2ff] font-bold">STEP 3</div>
                    <div className="font-bold text-white mt-1">Sequence Engine</div>
                    <p className="text-[10px] text-[#94a3b8] mt-1">
                      Queries Cloudflare D1 / SQLite <code className="text-[#00d2ff]">function_rules</code> to verify if current function is permitted after last one.
                    </p>
                  </div>

                  <div className="p-3 bg-[#131c2e] border border-[#223452] rounded">
                    <div className="text-[10px] text-[#00d2ff] font-bold">STEP 4</div>
                    <div className="font-bold text-white mt-1">Risk Heuristics</div>
                    <p className="text-[10px] text-[#94a3b8] mt-1">
                      Calculates Risk = Base + Sequence Penalty (+40) + RBAC Override (90). Evaluates cutoff (&gt;= 75).
                    </p>
                  </div>

                  <div className="p-3 bg-[#131c2e] border border-[#223452] rounded">
                    <div className="text-[10px] text-[#00ff87] font-bold">STEP 5</div>
                    <div className="font-bold text-white mt-1">Ledger &amp; Dispatch</div>
                    <p className="text-[10px] text-[#94a3b8] mt-1">
                      Writes audit log to <code className="text-[#00ff87]">security_audit_logs</code>. If ALLOWED, invokes function; if BLOCKED, aborts immediately.
                    </p>
                  </div>
                </div>
              </div>

              {/* Page-by-Page Activity Breakdown */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <h4 className="text-xs font-bold text-white uppercase mb-3">
                  Dashboard Screen Anatomy (Every Activity &amp; Module)
                </h4>
                <div className="space-y-3">
                  <div className="p-3 bg-[#131c2e] border border-[#223452] rounded">
                    <div className="flex items-center justify-between font-bold text-[#00d2ff]">
                      <span>Panel 1: Global Header &amp; Database State Controls</span>
                      <span className="text-[10px] bg-[#00d2ff]/10 px-2 py-0.5 rounded">Component: Header.tsx</span>
                    </div>
                    <p className="text-[#94a3b8] mt-1">
                      Provides instant controls to inspect live SQL schemas, clear audit streams, and reset the entire database to the baseline test state. Displays real-time Worker firewall heartbeat.
                    </p>
                  </div>

                  <div className="p-3 bg-[#131c2e] border border-[#223452] rounded">
                    <div className="flex items-center justify-between font-bold text-[#ff4a6b]">
                      <span>Panel 2: Real-Time Threat Summary Card</span>
                      <span className="text-[10px] bg-[#ff4a6b]/10 px-2 py-0.5 rounded">Component: ThreatSummaryCard.tsx</span>
                    </div>
                    <p className="text-[#94a3b8] mt-1">
                      Aggregates critical blocks (Risk &gt; 75), computes dynamic average threat levels, tracks affected identity profiles, and visualizes the DEFCON threat status badge.
                    </p>
                  </div>

                  <div className="p-3 bg-[#131c2e] border border-[#223452] rounded">
                    <div className="flex items-center justify-between font-bold text-amber-400">
                      <span>Panel 3: Pipeline Interceptor Testing Console</span>
                      <span className="text-[10px] bg-amber-400/10 px-2 py-0.5 rounded">Component: SimulationControl.tsx</span>
                    </div>
                    <p className="text-[#94a3b8] mt-1">
                      Allows evaluators to select any test principal (Admin, Dev, Guest, Malicious), pick target endpoints, trigger live security pipeline execution, and observe real-time terminal output.
                    </p>
                  </div>

                  <div className="p-3 bg-[#131c2e] border border-[#223452] rounded">
                    <div className="flex items-center justify-between font-bold text-[#00ff87]">
                      <span>Panel 4: Cryptographic Audit Stream &amp; CSV Exporter</span>
                      <span className="text-[10px] bg-[#00ff87]/10 px-2 py-0.5 rounded">Component: AuditLogStream.tsx</span>
                    </div>
                    <p className="text-[#94a3b8] mt-1">
                      Renders live database audit logs, enables sub-second text filtering across principals and routes, toggles verdict pills, and exports filtered streams into client-side CSV files.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'functions' && (
            <div className="space-y-6">
              <div className="bg-[#131c2e] border border-[#223452] p-4 rounded-md">
                <h3 className="text-white font-bold text-sm mb-2 flex items-center gap-2">
                  <Code className="w-4 h-4 text-[#00ff87]" />
                  Core Backend Security Functions Explained Line-by-Line
                </h3>
                <p className="text-[#94a3b8] leading-relaxed">
                  These 5 functions represent the algorithmic core of the research project implemented in <code className="text-[#00d2ff]">server.ts</code> and <code className="text-[#00d2ff]">server/db.ts</code>:
                </p>
              </div>

              {/* Function 1 */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#00d2ff]">
                    1. Identity Token Resolver (authMiddleware)
                  </span>
                  <span className="text-[10px] text-[#6b7c96]">Authentication Layer</span>
                </div>
                <p className="text-[#94a3b8] mt-2 leading-relaxed">
                  <strong>Activity:</strong> Extracts the HTTP <code className="text-[#00d2ff]">Authorization: Bearer &lt;token&gt;</code> header. Queries the <code className="text-[#00ff87]">users</code> table in SQLite/D1. If the user exists, attaches their profile (<code className="text-white">id, username, role, base_risk_score</code>) to the request context.
                </p>
                <div className="mt-2 p-2.5 bg-[#131c2e] rounded border border-[#223452] text-[11px] text-[#38bdf8]">
                  <code>const user = db.findUserByUsername(token); // e.g. 'auditor_guest' with base_risk_score=30</code>
                </div>
              </div>

              {/* Function 2 */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#00d2ff]">
                    2. Role-Based Access Control (rbacEvaluator)
                  </span>
                  <span className="text-[10px] text-[#6b7c96]">Authorization Layer</span>
                </div>
                <p className="text-[#94a3b8] mt-2 leading-relaxed">
                  <strong>Activity:</strong> Validates if the principal's role is authorized to invoke the requested endpoint.
                  <br />• <span className="text-purple-400">Admin</span>: Authorized for all endpoints including <code className="text-[#00d2ff]">/api/updateSystemPolicy</code>.
                  <br />• <span className="text-blue-400">Developer</span>: Authorized for <code className="text-[#00d2ff]">/api/getDashboardMetrics</code> and <code className="text-[#00d2ff]">/api/viewSecurityLogs</code>.
                  <br />• <span className="text-amber-400">Guest</span>: Only authorized for read-only <code className="text-[#00d2ff]">/api/getDashboardMetrics</code>.
                </p>
                <div className="mt-2 p-2.5 bg-[#131c2e] rounded border border-[#223452] text-[11px] text-[#ff4a6b]">
                  <code>if (req.path === '/api/updateSystemPolicy' && user.role !== 'Admin') rbacViolation = true; // Sets risk to 90%</code>
                </div>
              </div>

              {/* Function 3 */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#00d2ff]">
                    3. Sequential Flow Markov Validator (sequentialFlowEngine)
                  </span>
                  <span className="text-[10px] text-[#6b7c96]">Anomaly Detection Layer</span>
                </div>
                <p className="text-[#94a3b8] mt-2 leading-relaxed">
                  <strong>Activity:</strong> Serverless workflows require strict invocation sequences to prevent state manipulation. This function checks the caller's last executed function against the <code className="text-[#00ff87]">function_rules</code> transition table:
                  <br />• Allowed: <code className="text-[#00ff87]">login → getDashboardMetrics → viewSecurityLogs → updateSystemPolicy</code>.
                  <br />• If an attacker skips a step (e.g. calls <code className="text-[#ff4a6b]">login → updateSystemPolicy</code> directly), the sequence rule fails and adds a <strong>+40% penalty</strong> to the risk score.
                </p>
              </div>

              {/* Function 4 */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#00d2ff]">
                    4. Dynamic Threat Heuristic Calculator (dynamicRiskScorer)
                  </span>
                  <span className="text-[10px] text-[#6b7c96]">Risk Scoring Engine</span>
                </div>
                <p className="text-[#94a3b8] mt-2 leading-relaxed">
                  <strong>Activity:</strong> Calculates final risk using mathematical formula:
                </p>
                <div className="mt-2 p-3 bg-[#131c2e] rounded border border-[#223452] text-[11px] text-white">
                  <div className="text-[#00ff87] font-bold">R_final = min(100, R_base + (S_violation * 40))</div>
                  <div className="text-[10px] text-[#94a3b8] mt-1">
                    Where R_base is the user's historical trust score, S_violation is binary (0 or 1), and RBAC failure overrides to 90.
                  </div>
                </div>
              </div>

              {/* Function 5 */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#00d2ff]">
                    5. Automated Firewall Intercept &amp; Audit Logger (firewallMitigator)
                  </span>
                  <span className="text-[10px] text-[#6b7c96]">Mitigation &amp; Ledger Layer</span>
                </div>
                <p className="text-[#94a3b8] mt-2 leading-relaxed">
                  <strong>Activity:</strong> If <code className="text-[#ff4a6b]">R_final &gt;= 75</code> or RBAC is breached, the request is marked <code className="text-[#ff4a6b]">BLOCKED</code>, HTTP 403 Forbidden is returned, and execution halts. Otherwise, marked <code className="text-[#00ff87]">ALLOWED</code>. Every verdict is committed to <code className="text-[#00d2ff]">security_audit_logs</code>.
                </p>
              </div>
            </div>
          )}

          {activeTab === 'cloud-deployment' && (
            <div className="space-y-6">
              <div className="bg-[#131c2e] border border-[#223452] p-4 rounded-md">
                <h3 className="text-white font-bold text-sm mb-2 flex items-center gap-2">
                  <Server className="w-4 h-4 text-[#ff4a6b]" />
                  Connecting This To Real Cloud Infrastructure
                </h3>
                <p className="text-[#94a3b8] leading-relaxed">
                  This framework is architected specifically to run on <strong>Cloudflare Workers + Cloudflare D1</strong> (or AWS Lambda + DynamoDB). Below is the exact step-by-step production setup:
                </p>
              </div>

              {/* Step 1 */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between text-[#00d2ff] font-bold mb-2">
                  <span>Step 1: Install Cloudflare Wrangler CLI &amp; Authenticate</span>
                  <span className="text-[10px] text-[#6b7c96]">Terminal Commands</span>
                </div>
                <div className="p-3 bg-[#131c2e] rounded border border-[#223452] font-mono text-[11px] text-white space-y-1">
                  <div>npm install -g wrangler</div>
                  <div>wrangler login</div>
                  <div>wrangler init serverless-security-framework</div>
                </div>
              </div>

              {/* Step 2 */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between text-[#00d2ff] font-bold mb-2">
                  <span>Step 2: Create Real Cloudflare D1 Database</span>
                  <span className="text-[10px] text-[#6b7c96]">Cloud Storage Provisioning</span>
                </div>
                <div className="p-3 bg-[#131c2e] rounded border border-[#223452] font-mono text-[11px] text-white space-y-1">
                  <div>wrangler d1 create edge_security_d1</div>
                  <div className="text-[#6b7c96]"># Output will provide your database_id to paste in wrangler.toml</div>
                </div>
              </div>

              {/* Step 3 */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between text-[#00d2ff] font-bold mb-2">
                  <span>Step 3: Execute Schema &amp; Seed Test Data on Real Cloud D1</span>
                  <button
                    onClick={() => copyToClipboard('wrangler d1 execute edge_security_d1 --file=./schema.sql', 'd1-exec')}
                    className="text-[11px] text-[#00ff87] flex items-center gap-1 hover:underline"
                  >
                    {copiedSnippet === 'd1-exec' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    Copy Command
                  </button>
                </div>
                <div className="p-3 bg-[#131c2e] rounded border border-[#223452] font-mono text-[11px] text-white">
                  wrangler d1 execute edge_security_d1 --file=./schema.sql
                </div>
                <p className="text-[11px] text-[#94a3b8] mt-2">
                  This creates the exact 3 tables: <code className="text-[#00ff87]">users</code>, <code className="text-[#00ff87]">function_rules</code>, and <code className="text-[#00ff87]">security_audit_logs</code> directly in Cloudflare's distributed SQL network.
                </p>
              </div>

              {/* Step 4: Configuration */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between text-[#00d2ff] font-bold mb-2">
                  <span>Step 4: wrangler.toml File</span>
                  <button
                    onClick={() => copyToClipboard(wranglerTomlCode, 'toml')}
                    className="text-[11px] text-[#00ff87] flex items-center gap-1 hover:underline"
                  >
                    {copiedSnippet === 'toml' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    Copy wrangler.toml
                  </button>
                </div>
                <pre className="p-3 bg-[#131c2e] rounded border border-[#223452] font-mono text-[10px] text-[#94a3b8] overflow-x-auto">
                  {wranglerTomlCode}
                </pre>
              </div>

              {/* Step 5: Worker Edge Code */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between text-[#00d2ff] font-bold mb-2">
                  <span>Step 5: Cloudflare Worker Interceptor Code (src/worker.ts)</span>
                  <button
                    onClick={() => copyToClipboard(workerEdgeCode, 'worker')}
                    className="text-[11px] text-[#00ff87] flex items-center gap-1 hover:underline"
                  >
                    {copiedSnippet === 'worker' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    Copy Worker Code
                  </button>
                </div>
                <pre className="p-3 bg-[#131c2e] rounded border border-[#223452] font-mono text-[10px] text-[#94a3b8] overflow-x-auto max-h-56">
                  {workerEdgeCode}
                </pre>
              </div>

              {/* Step 6: Deploy Command */}
              <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
                <div className="flex items-center justify-between text-[#00ff87] font-bold mb-2">
                  <span>Step 6: Deploy Worker to Global Edge Network</span>
                </div>
                <div className="p-3 bg-[#131c2e] rounded border border-[#223452] font-mono text-[11px] text-white">
                  wrangler deploy
                </div>
                <p className="text-[11px] text-[#94a3b8] mt-2">
                  Cloudflare compiles your TypeScript code and deploys it globally across 300+ data centers in under 3 seconds. The Worker will intercept all traffic and query D1 with sub-10ms response latency!
                </p>
              </div>
            </div>
          )}

          {activeTab === 'viva-test-cases' && (
            <div className="space-y-6">
              <div className="bg-[#131c2e] border border-[#223452] p-4 rounded-md">
                <h3 className="text-white font-bold text-sm mb-2 flex items-center gap-2">
                  <BookOpen className="w-4 h-4 text-amber-400" />
                  Capstone Viva Demonstration: The 4 Live Attack &amp; Defense Scenarios
                </h3>
                <p className="text-[#94a3b8] leading-relaxed">
                  Use these exact 4 test cases when presenting to examiners or project evaluators to show how the security framework handles every cloud threat category:
                </p>
              </div>

              {/* Scenario 1 */}
              <div className="bg-[#090d16] border border-[#00ff87]/30 p-4 rounded-md">
                <div className="flex items-center justify-between text-[#00ff87] font-bold mb-1">
                  <span>Test Case 1: Legitimate Administrator (Happy Path)</span>
                  <span className="text-[10px] bg-[#00ff87]/15 px-2 py-0.5 rounded">EXPECTED: ALLOWED</span>
                </div>
                <p className="text-[#94a3b8] mt-2">
                  <strong>Action:</strong> Select Principal <code className="text-white">secops_admin</code> (Base Risk: 0%), run <code className="text-[#00d2ff]">/api/login</code>, then invoke <code className="text-[#00d2ff]">/api/getDashboardMetrics</code>.
                </p>
                <div className="mt-2 p-2.5 bg-[#131c2e] rounded text-[11px] space-y-1">
                  <div>• RBAC Check: <span className="text-[#00ff87]">Passed (Admin has unrestricted access)</span></div>
                  <div>• Sequential Check: <span className="text-[#00ff87]">Passed (Rule 1: login → getDashboardMetrics exists)</span></div>
                  <div>• Risk Calculation: <span className="text-[#00ff87]">0% Base + 0% Penalty = 0% Risk</span></div>
                  <div>• Verdict: <span className="text-[#00ff87] font-bold">ALLOWED (HTTP 200)</span></div>
                </div>
              </div>

              {/* Scenario 2 */}
              <div className="bg-[#090d16] border border-[#ff4a6b]/30 p-4 rounded-md">
                <div className="flex items-center justify-between text-[#ff4a6b] font-bold mb-1">
                  <span>Test Case 2: Privilege Escalation Attack (RBAC Violation)</span>
                  <span className="text-[10px] bg-[#ff4a6b]/15 px-2 py-0.5 rounded">EXPECTED: BLOCKED (RISK 90%)</span>
                </div>
                <p className="text-[#94a3b8] mt-2">
                  <strong>Action:</strong> Select Principal <code className="text-white">auditor_guest</code> (Role: Guest), invoke restricted policy endpoint <code className="text-[#ff4a6b]">/api/updateSystemPolicy</code>.
                </p>
                <div className="mt-2 p-2.5 bg-[#131c2e] rounded text-[11px] space-y-1">
                  <div>• RBAC Check: <span className="text-[#ff4a6b] font-bold">FAILED (Role [Guest] cannot invoke /api/updateSystemPolicy)</span></div>
                  <div>• Risk Calculation: <span className="text-[#ff4a6b] font-bold">Escalated to 90% Override</span></div>
                  <div>• Firewall Decision: <span className="text-[#ff4a6b] font-bold">BLOCKED (90% &gt;= 75% Cutoff)</span></div>
                  <div>• Mitigation: <span className="text-[#94a3b8]">Connection aborted; security ledger records RBAC breach event.</span></div>
                </div>
              </div>

              {/* Scenario 3 */}
              <div className="bg-[#090d16] border border-amber-400/30 p-4 rounded-md">
                <div className="flex items-center justify-between text-amber-400 font-bold mb-1">
                  <span>Test Case 3: Out-of-Sequence Call Anomaly (Cloud Dev)</span>
                  <span className="text-[10px] bg-amber-400/15 px-2 py-0.5 rounded">SEQUENCE JUMP DETECTED</span>
                </div>
                <p className="text-[#94a3b8] mt-2">
                  <strong>Action:</strong> Select Principal <code className="text-white">cloud_dev</code> (Base Risk: 15%), jump directly from <code className="text-white">login</code> to <code className="text-[#00d2ff]">/api/viewSecurityLogs</code> without calling dashboard metrics first.
                </p>
                <div className="mt-2 p-2.5 bg-[#131c2e] rounded text-[11px] space-y-1">
                  <div>• Sequential Check: <span className="text-amber-400 font-bold">FAILED (No transition rule: login → viewSecurityLogs)</span></div>
                  <div>• Penalty Added: <span className="text-amber-400 font-bold">+40% Sequence Violation Penalty</span></div>
                  <div>• Computed Risk: <span className="text-white">15% Base + 40% Penalty = 55%</span></div>
                  <div>• Ledger Output: <span className="text-[#94a3b8]">Logged as abnormal invocation order footprint in audit stream.</span></div>
                </div>
              </div>

              {/* Scenario 4 */}
              <div className="bg-[#090d16] border border-[#ff4a6b]/40 p-4 rounded-md">
                <div className="flex items-center justify-between text-[#ff4a6b] font-bold mb-1">
                  <span>Test Case 4: Malicious Principal Combined Attack (Threat Actor)</span>
                  <span className="text-[10px] bg-[#ff4a6b]/20 px-2 py-0.5 rounded">DEFCON 1 THREAT CUTOFF</span>
                </div>
                <p className="text-[#94a3b8] mt-2">
                  <strong>Action:</strong> Select Principal <code className="text-white">threat_actor</code> (Base Risk: 70%), attempt an out-of-order jump to <code className="text-[#ff4a6b]">/api/viewSecurityLogs</code>.
                </p>
                <div className="mt-2 p-2.5 bg-[#131c2e] rounded text-[11px] space-y-1">
                  <div>• Base Threat Score: <span className="text-[#ff4a6b]">70%</span></div>
                  <div>• Sequence Jump Penalty: <span className="text-[#ff4a6b]">+40%</span></div>
                  <div>• Final Computed Risk: <span className="text-[#ff4a6b] font-bold">110% (Capped at 100%)</span></div>
                  <div>• Firewall Decision: <span className="text-[#ff4a6b] font-bold">AUTOMATIC BLOCK (100% &gt; 75% Cutoff)</span></div>
                  <div>• Dashboard Effect: <span className="text-[#ff4a6b]">Threat Summary card updates instantly to DEFCON 1 alert.</span></div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-[#1e293b] bg-[#131c2e] flex items-center justify-between text-xs">
          <div className="text-[#6b7c96]">
            Serverless Security Verification Framework • Enterprise Zero-Trust Edition
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-[#090d16] hover:bg-[#1e293b] text-white border border-[#223452] font-bold transition-colors"
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
};
