import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  Play,
  Activity,
  Terminal,
  Server,
  UserCheck,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  Info
} from 'lucide-react';
import { User, SecurityAuditLog, AuthSession } from '../types.ts';

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

  const guestLogs = logs.filter(
    (l) => l.username.toLowerCase() === currentSession.user.username.toLowerCase()
  );

  const handleInvokePermitted = async () => {
    setTestingEndpoint('getDashboardMetrics');
    try {
      await onFireFunction('getDashboardMetrics');
      // Fetch fresh metrics response for display in the portal
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

  const roleClearanceMatrix = [
    {
      name: 'getDashboardMetrics',
      route: '/api/getDashboardMetrics',
      tier: 'Tier 1',
      allowed: true,
      description: 'Public health metrics, cluster telemetry, and node status.',
      accessBadge: 'Permitted (Guest Clearance)'
    },
    {
      name: 'viewSecurityLogs',
      route: '/api/viewSecurityLogs',
      tier: 'Tier 2',
      allowed: false,
      description: 'Distributed D1 security audit logs and sequence records.',
      accessBadge: 'Requires Developer or Admin'
    },
    {
      name: 'deployWorkerCode',
      route: '/api/deployWorkerCode',
      tier: 'Tier 2',
      allowed: false,
      description: 'Deploy V8 isolate serverless bundles to edge nodes.',
      accessBadge: 'Requires Developer or Admin'
    },
    {
      name: 'updateSystemPolicy',
      route: '/api/updateSystemPolicy',
      tier: 'Tier 3',
      allowed: false,
      description: 'Push Markov rules and dynamic defense thresholds.',
      accessBadge: 'Admin Only'
    },
    {
      name: 'rotateEncryptionKeys',
      route: '/api/rotateEncryptionKeys',
      tier: 'Tier 3',
      allowed: false,
      description: 'Rotate master cryptographic KMS keys.',
      accessBadge: 'Admin Only'
    },
    {
      name: 'purgeColdStorageBackups',
      route: '/api/purgeColdStorageBackups',
      tier: 'Tier 3',
      allowed: false,
      description: 'Purge distributed audit archive volumes.',
      accessBadge: 'Admin Only'
    }
  ];

  return (
    <div className="space-y-6 font-sans">
      {/* 1. GUEST IDENTITY & CLEARANCE HERO */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="p-3 rounded-xl border bg-emerald-500/10 border-emerald-500/30 text-emerald-400">
              <UserCheck className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h2 className="text-lg font-bold text-white tracking-tight">
                  Guest Identity &amp; Telemetry Workspace
                </h2>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-bold">
                  Role: Guest (Tier 1 Read-Only)
                </span>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
                  Principal: {currentSession.user.username}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                You are authenticated with limited Guest privileges under the Zero-Trust Principle of Least Privilege (PoLP).
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs">
            <div>
              <span className="text-slate-500 text-[10px] block uppercase">Base Risk Score</span>
              <span className="text-emerald-400 font-bold text-sm">{currentSession.user.base_risk_score}%</span>
            </div>
            <div className="h-6 w-px bg-slate-800" />
            <div>
              <span className="text-slate-500 text-[10px] block uppercase">Auth Scheme</span>
              <span className="text-white font-bold text-xs">HMAC-SHA256</span>
            </div>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-400">
          <span>Session Token: <code className="text-slate-300 font-mono">{currentSession.token}</code></span>
          <span className="text-emerald-400 font-mono">Status: Authenticated &amp; Sandboxed</span>
        </div>
      </div>

      {/* 2. INTERACTIVE PERMITTED FUNCTION INVOKER */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Permitted Action Card */}
        <div className="rounded-xl border border-emerald-500/30 bg-slate-900/80 p-5 shadow-lg flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-emerald-400" />
                <h3 className="font-bold text-white text-sm uppercase tracking-wider">
                  Permitted Serverless Function
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 font-semibold">
                Authorization Granted
              </span>
            </div>

            <div className="space-y-3">
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="flex items-center justify-between">
                  <code className="text-sm font-bold text-emerald-400 font-mono">
                    /api/getDashboardMetrics
                  </code>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded">
                    GET • Tier 1
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-2">
                  Fetches public cluster metrics, system node health, and live edge runtime configuration. This route is accessible by all roles including Guests.
                </p>
              </div>

              {testResult && (
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">
                    Live Response Payload:
                  </span>
                  <pre className="text-emerald-300 text-[11px] overflow-x-auto max-h-40 scrollbar-thin">
                    {JSON.stringify(testResult, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>

          <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">Expected Result: 200 OK</span>
            <button
              type="button"
              onClick={handleInvokePermitted}
              disabled={isFiring || testingEndpoint === 'getDashboardMetrics'}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white shadow-md transition-colors disabled:opacity-50"
            >
              {testingEndpoint === 'getDashboardMetrics' ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Invoking Route...
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-white" />
                  Execute Permitted Function
                </>
              )}
            </button>
          </div>
        </div>

        {/* Zero-Trust RBAC Enforcement Test */}
        <div className="rounded-xl border border-rose-500/30 bg-slate-900/80 p-5 shadow-lg flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <h3 className="font-bold text-white text-sm uppercase tracking-wider">
                  Zero-Trust RBAC Enforcement Test
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 font-semibold">
                Access Restricted
              </span>
            </div>

            <div className="space-y-3">
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="flex items-center justify-between">
                  <code className="text-sm font-bold text-rose-400 font-mono">
                    /api/deployWorkerCode
                  </code>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded">
                    POST • Tier 2
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-2">
                  Testing what happens when a Guest principal attempts to invoke privileged Tier 2 or Tier 3 routes. The Cloudflare Edge Interceptor will evaluate RBAC and immediately reject the request.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-rose-950/20 border border-rose-500/20 text-xs text-rose-300 space-y-1 font-mono">
                <div className="font-bold text-rose-400 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5" />
                  Expected Firewall Interception:
                </div>
                <div className="text-[11px] text-slate-300">
                  HTTP 403 Forbidden: "RBAC Breach: Role 'Guest' unauthorized for Tier 2 endpoint."
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">Expected Result: 403 Forbidden</span>
            <button
              type="button"
              onClick={() => handleTestUnauthorized('deployWorkerCode')}
              disabled={isFiring || testingEndpoint === 'deployWorkerCode'}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white shadow-md transition-colors disabled:opacity-50"
            >
              {testingEndpoint === 'deployWorkerCode' ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Testing Interceptor...
                </>
              ) : (
                <>
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Trigger Interception Demo
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* 3. ROLE CLEARANCE MATRIX & FUNCTION PERMISSIONS */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            <h3 className="font-bold text-white text-sm uppercase tracking-wider">
              System Function Role Clearance Matrix
            </h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Evaluated per request at Edge
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="pb-2 font-bold">Function Name</th>
                <th className="pb-2 font-bold">Tier</th>
                <th className="pb-2 font-bold">Your Clearance</th>
                <th className="pb-2 font-bold">Function Description</th>
                <th className="pb-2 font-bold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {roleClearanceMatrix.map((item) => (
                <tr key={item.name} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 pr-4 font-bold text-white">
                    <div className="flex items-center gap-2">
                      {item.allowed ? (
                        <Unlock className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Lock className="w-3.5 h-3.5 text-slate-500" />
                      )}
                      <span>{item.name}</span>
                    </div>
                  </td>
                  <td className="py-3 pr-4 text-slate-400">{item.tier}</td>
                  <td className="py-3 pr-4">
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-semibold border ${
                        item.allowed
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {item.accessBadge}
                    </span>
                  </td>
                  <td className="py-3 pr-4 text-slate-300 text-xs font-sans">
                    {item.description}
                  </td>
                  <td className="py-3 text-right">
                    <button
                      type="button"
                      onClick={() =>
                        item.allowed
                          ? handleInvokePermitted()
                          : handleTestUnauthorized(item.name)
                      }
                      disabled={isFiring || testingEndpoint === item.name}
                      className={`px-2.5 py-1 rounded text-xs font-bold transition-colors ${
                        item.allowed
                          ? 'bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40'
                          : 'bg-slate-800 hover:bg-slate-700 text-slate-400 border border-slate-700'
                      }`}
                    >
                      {item.allowed ? 'Invoke' : 'Test 403'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. PERSONAL REQUEST AUDIT LEDGER */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-blue-400" />
            <h3 className="font-bold text-white text-sm uppercase tracking-wider">
              My Execution Audit Ledger ({guestLogs.length} Records)
            </h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Filtered to principal: {currentSession.user.username}
          </span>
        </div>

        {guestLogs.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs font-mono">
            No activity records found for this guest session yet. Click "Execute Permitted Function" or "Trigger Interception Demo" above to generate audit events.
          </div>
        ) : (
          <div className="space-y-2 font-mono text-xs max-h-60 overflow-y-auto scrollbar-thin">
            {guestLogs.slice(0, 10).map((log) => (
              <div
                key={log.id}
                className={`p-3 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                  log.status === 'ALLOWED'
                    ? 'bg-emerald-950/20 border-emerald-500/30'
                    : 'bg-rose-950/20 border-rose-500/30'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                      log.status === 'ALLOWED'
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : 'bg-rose-500/20 text-rose-400'
                    }`}
                  >
                    {log.status}
                  </span>
                  <code className="text-white font-bold">{log.requested_function}</code>
                  <span className="text-slate-400 text-[11px]">
                    Risk: <strong className={log.calculated_risk > 50 ? 'text-rose-400' : 'text-emerald-400'}>{log.calculated_risk}%</strong>
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 sm:text-right">
                  <span>{log.reason}</span>
                  <span className="ml-2 text-slate-500 text-[10px]">{log.timestamp}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 5. LEAST PRIVILEGE ARCHITECTURE NOTICE */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-950 text-xs text-slate-400 flex items-start gap-3">
        <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-bold text-white">
            NIST SP 800-207 Zero-Trust Isolation Architecture
          </div>
          <p>
            In accordance with the Principle of Least Privilege (PoLP), guest principals are strictly restricted from viewing developer code pipelines, modifying security policies, or accessing administrative command centers. Switch to a Developer or Administrator account to explore higher clearance capabilities.
          </p>
        </div>
      </div>
    </div>
  );
};
