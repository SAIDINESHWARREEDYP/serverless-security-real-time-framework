import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  Unlock,
  Play,
  Activity,
  UserCheck,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  CheckCircle2,
  Sparkles,
  Send,
  Building,
  KeyRound,
  FileCheck,
  Fingerprint,
  Layers
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { SecurityAuditLog, AuthSession } from '../types.ts';

interface GuestPortalProps {
  currentSession: AuthSession;
  logs: SecurityAuditLog[];
  onFireFunction: (functionName: string) => Promise<void>;
  isFiring?: boolean;
}

export const GuestPortal: React.FC<GuestPortalProps> = ({
  currentSession,
  logs,
  onFireFunction,
  isFiring = false
}) => {
  const [testResult, setTestResult] = useState<any | null>(null);
  const [testingEndpoint, setTestingEndpoint] = useState<string | null>(null);
  const [escalationJustification, setEscalationJustification] = useState('');
  const [escalationSubmitted, setEscalationSubmitted] = useState(false);
  const [activeTab, setActiveTab] = useState<'passport' | 'actions' | 'compliance'>('passport');

  const guestLogs = logs.filter(
    (l) => l.username.toLowerCase() === currentSession.user.username.toLowerCase()
  );

  const handleInvokePermitted = async () => {
    setTestingEndpoint('getDashboardMetrics');
    try {
      await onFireFunction('getDashboardMetrics');
      const res = await fetch('/api/getDashboardMetrics', {
        headers: {
          Authorization: `Bearer ${currentSession.token}`
        }
      });
      const data = await res.json();
      setTestResult(data);
    } catch (err: any) {
      setTestResult({ error: err?.message || 'Request failed' });
    } finally {
      setTestingEndpoint(null);
    }
  };

  const handleTestUnauthorized = async (endpoint: string) => {
    setTestingEndpoint(endpoint);
    try {
      await onFireFunction(endpoint);
    } finally {
      setTestingEndpoint(null);
    }
  };

  const handleEscalateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!escalationJustification.trim()) return;
    setEscalationSubmitted(true);
    setTimeout(() => {
      setEscalationJustification('');
    }, 3000);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="space-y-6 font-sans"
    >
      {/* 1. CORPORATE ACCESS PORTAL BANNER */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 shrink-0">
              <UserCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-base sm:text-lg font-bold text-white tracking-tight">
                  Corporate Employee &amp; Guest Access Portal
                </h2>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-bold">
                  Tier 1 Clearance // Least Privilege
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                Zero-Trust authenticated user workstation. Clean personal clearance passport, permitted corporate business endpoints, and compliance status.
              </p>
            </div>
          </div>

          {/* Sub-tab Navigation */}
          <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
            <button
              onClick={() => setActiveTab('passport')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                activeTab === 'passport'
                  ? 'bg-emerald-600 text-white font-medium'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Digital Passport
            </button>
            <button
              onClick={() => setActiveTab('actions')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                activeTab === 'actions'
                  ? 'bg-emerald-600 text-white font-medium'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Permitted Operations
            </button>
            <button
              onClick={() => setActiveTab('compliance')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                activeTab === 'compliance'
                  ? 'bg-emerald-600 text-white font-medium'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Compliance Posture
            </button>
          </div>
        </div>
      </div>

      {/* VIEW 1: DIGITAL IDENTITY PASSPORT */}
      {activeTab === 'passport' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Holographic Security Passport Card */}
          <div className="lg:col-span-7">
            <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 border border-emerald-500/30 shadow-xl relative overflow-hidden font-mono">
              {/* Background Security Watermark Pattern */}
              <div className="absolute -right-8 -bottom-8 opacity-5 pointer-events-none">
                <ShieldCheck className="w-64 h-64 text-emerald-400" />
              </div>

              <div className="flex items-start justify-between border-b border-slate-800 pb-4 mb-5">
                <div>
                  <div className="text-[10px] text-emerald-400 uppercase tracking-widest font-bold">
                    CORPORATE IDENTITY SECURITY PASSPORT
                  </div>
                  <div className="text-xl font-bold text-white mt-1">
                    {currentSession.user.username}
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5">
                    {currentSession.user.department || 'General Operations & Compliance'}
                  </div>
                </div>

                <div className="text-right">
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-bold">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    {currentSession.user.status || 'APPROVED'}
                  </span>
                  <div className="text-[10px] text-slate-500 mt-1">Status Verified</div>
                </div>
              </div>

              {/* Passport Specs Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-5 text-xs">
                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 uppercase block">Role Clearance</span>
                  <strong className="text-white text-sm">{currentSession.user.role}</strong>
                </div>

                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 uppercase block">Risk Profile</span>
                  <strong className="text-emerald-400 text-sm">{currentSession.user.base_risk_score}% (Nominal)</strong>
                </div>

                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 uppercase block">Cryptographic Scheme</span>
                  <strong className="text-white text-xs">HMAC-SHA256</strong>
                </div>

                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 uppercase block">Session Inception</span>
                  <strong className="text-slate-300 text-xs">{currentSession.loginTime}</strong>
                </div>

                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 sm:col-span-2">
                  <span className="text-[10px] text-slate-500 uppercase block">JWT Signature Token</span>
                  <code className="text-slate-300 text-[11px] truncate block">
                    {currentSession.token}
                  </code>
                </div>
              </div>

              {/* Principle of Least Privilege Notice */}
              <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-emerald-300/90 text-xs flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>
                  Protected under Zero-Trust architecture. Invocations are strictly bound to Tier 1 business endpoints.
                </span>
              </div>
            </div>
          </div>

          {/* Right Column: Clearance Escalation Request Card */}
          <div className="lg:col-span-5 space-y-4">
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-sm font-mono text-xs">
              <div className="flex items-center gap-2 pb-3 mb-3 border-b border-slate-800 text-white font-bold">
                <KeyRound className="w-4 h-4 text-blue-400" />
                Request Role Clearance Escalation
              </div>
              <p className="text-slate-400 text-xs mb-3 font-sans">
                Need temporary Developer or elevated privileges for an approved project or sprint? Submit an access justification to SecOps:
              </p>

              {escalationSubmitted ? (
                <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/30 text-emerald-300 text-xs space-y-1 text-center">
                  <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-1" />
                  <strong className="block text-white">Escalation Request Dispatched</strong>
                  <p className="text-[11px] text-slate-400">SecOps administrators have received your request for review.</p>
                </div>
              ) : (
                <form onSubmit={handleEscalateSubmit} className="space-y-3">
                  <div>
                    <label className="block text-[11px] text-slate-300 mb-1">
                      Project Justification &amp; Ticket ID:
                    </label>
                    <textarea
                      value={escalationJustification}
                      onChange={(e) => setEscalationJustification(e.target.value)}
                      rows={3}
                      placeholder="e.g. JIRA-4092: Need Developer access for Cloudflare isolate deployment testing."
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={!escalationJustification.trim()}
                    className="w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Submit Escalation to Admin</span>
                  </button>
                </form>
              )}
            </div>

            {/* My Personal Access Events */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
                <span className="text-white font-semibold">My Access Events ({guestLogs.length})</span>
                <span className="text-[10px] text-slate-500">Live Audit</span>
              </div>
              <div className="space-y-1 max-h-36 overflow-y-auto">
                {guestLogs.length > 0 ? (
                  guestLogs.map((l) => (
                    <div
                      key={l.id}
                      className="p-1.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between text-[11px]"
                    >
                      <code className="text-slate-300 truncate">{l.requested_function}</code>
                      <span className={`text-[10px] px-1 rounded ${
                        l.status === 'ALLOWED' ? 'text-emerald-400 bg-emerald-500/10' : 'text-rose-400 bg-rose-500/10'
                      }`}>
                        {l.status}
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-3 text-slate-500 text-xs">
                    No recent activity logged for this user.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 2: PERMITTED OPERATIONS */}
      {activeTab === 'actions' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Permitted Operation Card */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-emerald-500/30 font-mono text-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-white font-bold flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                Permitted Serverless Route: /api/getDashboardMetrics
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                Tier 1 Read-Only
              </span>
            </div>

            <p className="text-slate-400 text-xs font-sans">
              Queries public cluster metrics, system node health, and edge runtime configurations. Cleared for all corporate principals.
            </p>

            <button
              onClick={handleInvokePermitted}
              disabled={isFiring || testingEndpoint === 'getDashboardMetrics'}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors disabled:opacity-50"
            >
              <Play className={`w-3.5 h-3.5 ${testingEndpoint === 'getDashboardMetrics' ? 'animate-spin' : ''}`} />
              <span>{testingEndpoint === 'getDashboardMetrics' ? 'Querying Route...' : 'Execute Permitted Route'}</span>
            </button>

            {testResult && (
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                <span className="text-slate-500 text-[10px] block mb-1">Payload Response:</span>
                <pre className="text-emerald-300 text-[11px] overflow-x-auto max-h-48">
                  {JSON.stringify(testResult, null, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* Attempt High-Tier Action to Demonstrate Zero-Trust RBAC */}
          <div className="p-5 rounded-xl bg-slate-900/90 border border-rose-500/30 font-mono text-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-white font-bold flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Zero-Trust Enforcement Test (Simulate Block)
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
                Tier 2/3 Guarded
              </span>
            </div>

            <p className="text-slate-400 text-xs font-sans">
              Test invoking a restricted function like <code>deployWorkerCode</code> or <code>updateSystemPolicy</code>. Zero-Trust will immediately intercept and log the RBAC violation.
            </p>

            <div className="flex items-center gap-2">
              <button
                onClick={() => handleTestUnauthorized('deployWorkerCode')}
                disabled={isFiring || testingEndpoint === 'deployWorkerCode'}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/60 font-semibold text-xs transition-colors disabled:opacity-50"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Test /deployWorkerCode</span>
              </button>

              <button
                onClick={() => handleTestUnauthorized('updateSystemPolicy')}
                disabled={isFiring || testingEndpoint === 'updateSystemPolicy'}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/60 font-semibold text-xs transition-colors disabled:opacity-50"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Test /updateSystemPolicy</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 3: COMPLIANCE POSTURE */}
      {activeTab === 'compliance' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
          <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center gap-2 text-white font-semibold">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Multi-Factor Authentication (MFA)
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Session is bound to an authenticated identity with zero unencrypted credentials stored client-side.
            </p>
          </div>

          <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center gap-2 text-white font-semibold">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Principle of Least Privilege (PoLP)
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              All Tier 2 &amp; Tier 3 functions are restricted at the edge firewall, preventing privilege escalation.
            </p>
          </div>

          <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center gap-2 text-white font-semibold">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Real-Time Audit Trail
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Every request calculates dynamic Markov risk and writes an immutable audit record to the security ledger.
            </p>
          </div>
        </div>
      )}
    </motion.div>
  );
};
