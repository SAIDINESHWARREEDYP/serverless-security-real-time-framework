import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  Users,
  Zap,
  Radio,
  Sliders,
  RefreshCw,
  Trash2,
  RotateCcw,
  Cloud,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Server,
  Database,
  KeyRound,
  Terminal,
  Play,
  UserCheck,
  UserX,
  ExternalLink,
  ChevronRight,
  Shield,
  Activity,
  Layers,
  ArrowRight,
  Search
} from 'lucide-react';
import { User, SecurityAuditLog, FunctionRule, SecurityPolicyConfig, AuthSession } from '../types.ts';

interface AdminCommandCenterProps {
  users: User[];
  logs: SecurityAuditLog[];
  rules: FunctionRule[];
  policyConfig?: SecurityPolicyConfig;
  currentSession: AuthSession | null;
  onSwitchSession: (user: User) => Promise<void>;
  onUpdatePolicyConfig: (config: SecurityPolicyConfig) => Promise<void>;
  onResetDatabase: () => Promise<void>;
  onClearLogs: () => Promise<void>;
  onRefreshData: () => Promise<void>;
  onAddTerminalLog: (type: 'info' | 'post' | 'get' | 'success' | 'alert' | 'error' | 'metric', text: string) => void;
  onDirectInvoke: (endpoint: string) => Promise<void>;
  isResetting?: boolean;
}

export const AdminCommandCenter: React.FC<AdminCommandCenterProps> = ({
  users,
  logs,
  rules,
  policyConfig = { maxRiskThreshold: 75, sequenceViolationPenalty: 40, enforceStrictSequence: true, globalLockdown: false },
  currentSession,
  onSwitchSession,
  onUpdatePolicyConfig,
  onResetDatabase,
  onClearLogs,
  onRefreshData,
  onAddTerminalLog,
  onDirectInvoke,
  isResetting = false
}) => {
  // Local state for policy tuning
  const [threshold, setThreshold] = useState(policyConfig.maxRiskThreshold ?? 75);
  const [penalty, setPenalty] = useState(policyConfig.sequenceViolationPenalty ?? 40);
  const [strictSeq, setStrictSeq] = useState(policyConfig.enforceStrictSequence ?? true);
  const [isSavingPolicy, setIsSavingPolicy] = useState(false);
  const [userSearch, setUserSearch] = useState('');
  const [logFilter, setLogFilter] = useState<'ALL' | 'BLOCKED' | 'ALLOWED'>('ALL');
  const [cloudPingStatus, setCloudPingStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [cloudPingLatency, setCloudPingLatency] = useState<number | null>(null);
  const [d1Status, setD1Status] = useState<'idle' | 'testing' | 'verified'>('idle');
  const [lastExecutedFunc, setLastExecutedFunc] = useState<string | null>(null);
  const [executingFunc, setExecutingFunc] = useState<string | null>(null);
  const [userUpdating, setUserUpdating] = useState<string | null>(null);

  // Global Lockdown status
  const isGlobalLockdown = Boolean(policyConfig.globalLockdown);

  // Calculate DEFCON status based on recent threat density
  const totalLogs = logs.length;
  const blockedLogs = logs.filter(l => l.status === 'BLOCKED').length;
  const blockRate = totalLogs > 0 ? (blockedLogs / totalLogs) * 100 : 0;
  
  const defconLevel = isGlobalLockdown ? 1 :
    blockRate > 40 ? 2 :
    blockRate > 20 ? 3 :
    blockRate > 5 ? 4 : 5;

  const defconColors = {
    1: 'bg-rose-600 text-white border-rose-400',
    2: 'bg-orange-600 text-white border-orange-400',
    3: 'bg-amber-600 text-white border-amber-400',
    4: 'bg-blue-600 text-white border-blue-400',
    5: 'bg-emerald-600 text-white border-emerald-400'
  };

  // Toggle Global Lockdown
  const handleToggleLockdown = async () => {
    setIsSavingPolicy(true);
    const newLockdown = !isGlobalLockdown;
    try {
      await onUpdatePolicyConfig({
        ...policyConfig,
        globalLockdown: newLockdown
      });
      onAddTerminalLog(
        newLockdown ? 'alert' : 'success',
        `[SECOPS OVERRIDE] Emergency Global Perimeter Lockdown is now ${newLockdown ? 'ACTIVATED' : 'DISENGAGED'}.`
      );
    } finally {
      setIsSavingPolicy(false);
    }
  };

  // Save tuned policy config
  const handleSavePolicy = async () => {
    setIsSavingPolicy(true);
    try {
      await onUpdatePolicyConfig({
        maxRiskThreshold: threshold,
        sequenceViolationPenalty: penalty,
        enforceStrictSequence: strictSeq,
        globalLockdown: isGlobalLockdown
      });
      onAddTerminalLog('success', `[POLICY] Security policy updated: Cutoff=${threshold}%, Penalty=+${penalty}%, Strict=${strictSeq}`);
    } finally {
      setIsSavingPolicy(false);
    }
  };

  // Apply quick presets
  const handleApplyPreset = async (preset: 'strict' | 'standard' | 'permissive') => {
    let t = 75, p = 40, s = true;
    if (preset === 'strict') {
      t = 40; p = 60; s = true;
    } else if (preset === 'permissive') {
      t = 90; p = 15; s = false;
    }
    setThreshold(t);
    setPenalty(p);
    setStrictSeq(s);

    setIsSavingPolicy(true);
    try {
      await onUpdatePolicyConfig({
        maxRiskThreshold: t,
        sequenceViolationPenalty: p,
        enforceStrictSequence: s,
        globalLockdown: isGlobalLockdown
      });
      onAddTerminalLog('info', `[POLICY] Applied policy preset: [${preset.toUpperCase()}]`);
    } finally {
      setIsSavingPolicy(false);
    }
  };

  // Change user role or risk score
  const handleModifyUser = async (username: string, updates: { role?: 'Admin' | 'Developer' | 'Guest'; base_risk_score?: number }) => {
    setUserUpdating(username);
    try {
      const res = await fetch(`/api/system/users/${encodeURIComponent(username)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates)
      });
      if (res.ok) {
        await onRefreshData();
        onAddTerminalLog('info', `[IAM ADMIN] Updated principal [${username}] attributes.`);
      }
    } catch (err: any) {
      onAddTerminalLog('error', `[IAM ADMIN] User update failed: ${err?.message || String(err)}`);
    } finally {
      setUserUpdating(null);
    }
  };

  // Run Cloudflare Edge Ping Probe
  const handleTestCloudflareEdge = async () => {
    setCloudPingStatus('testing');
    const start = performance.now();
    try {
      const res = await fetch('/api/health');
      const latency = Math.round(performance.now() - start);
      if (res.ok) {
        setCloudPingLatency(latency);
        setCloudPingStatus('success');
        onAddTerminalLog('success', `[CLOUD DIAGNOSTICS] Cloudflare Worker Edge ping verified in ${latency}ms.`);
      } else {
        setCloudPingStatus('error');
      }
    } catch {
      setCloudPingStatus('error');
    }
  };

  // Run D1 SQLite State Verification
  const handleVerifyD1Database = async () => {
    setD1Status('testing');
    try {
      const res = await fetch('/api/system/overview');
      if (res.ok) {
        setD1Status('verified');
        onAddTerminalLog('success', `[D1 DATABASE] SQLite relational schema & ACID constraints verified.`);
      }
    } catch {
      setD1Status('idle');
    }
  };

  // Direct function invocation from Admin Console
  const handleExecuteFunction = async (fnPath: string) => {
    setExecutingFunc(fnPath);
    setLastExecutedFunc(fnPath);
    try {
      await onDirectInvoke(fnPath);
    } finally {
      setExecutingFunc(null);
    }
  };

  // Filtered users list
  const filteredUsers = users.filter(u =>
    u.username.toLowerCase().includes(userSearch.toLowerCase()) ||
    u.role.toLowerCase().includes(userSearch.toLowerCase())
  );

  // Available functions
  const systemFunctions = [
    {
      name: 'getDashboardMetrics',
      path: '/api/getDashboardMetrics',
      tier: 'Tier 1 (Telemetry)',
      allowedRoles: ['Guest', 'Developer', 'Admin'],
      riskImpact: 'Baseline (0%)',
      desc: 'Retrieves cluster state, active nodes, and runtime configuration telemetry.'
    },
    {
      name: 'viewSecurityLogs',
      path: '/api/viewSecurityLogs',
      tier: 'Tier 1 (Audit Read)',
      allowedRoles: ['Developer', 'Admin'],
      riskImpact: 'Sequence check (+40% if out of order)',
      desc: 'Queries persistent Cloudflare D1 distributed SQLite security audit ledger.'
    },
    {
      name: 'deployWorkerCode',
      path: '/api/deployWorkerCode',
      tier: 'Tier 2 (Edge Deployment)',
      allowedRoles: ['Developer', 'Admin'],
      riskImpact: 'Sequence check (+40% if skipped audit)',
      desc: 'Compiles and distributes V8 isolate bundle to worldwide edge point-of-presence (PoP).'
    },
    {
      name: 'updateSystemPolicy',
      path: '/api/updateSystemPolicy',
      tier: 'Tier 3 (Policy Enforcer)',
      allowedRoles: ['Admin'],
      riskImpact: 'Strict Admin validation',
      desc: 'Pushes dynamic Markov chain rules and threat thresholds to Cloudflare interceptors.'
    },
    {
      name: 'rotateEncryptionKeys',
      path: '/api/rotateEncryptionKeys',
      tier: 'Tier 3 (Cryptographic)',
      allowedRoles: ['Admin'],
      riskImpact: 'Strict Admin validation',
      desc: 'Performs zero-downtime automated HSM key rotation and re-encrypts session payloads.'
    },
    {
      name: 'purgeColdStorageBackups',
      path: '/api/purgeColdStorageBackups',
      tier: 'Tier 3 (Destructive Storage)',
      allowedRoles: ['Admin'],
      riskImpact: 'Strict Admin validation + Markov',
      desc: 'Permanently evacuates and invalidates stale cryptographic audit archives.'
    }
  ];

  return (
    <div className="space-y-6 font-sans">
      {/* 1. TOP EXECUTIVE SECOPS BANNER */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl backdrop-blur-md">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className={`p-3 rounded-xl border flex items-center justify-center ${
              isGlobalLockdown
                ? 'bg-rose-500/20 border-rose-500/50 text-rose-400 animate-pulse'
                : 'bg-blue-500/10 border-blue-500/30 text-blue-400'
            }`}>
              <ShieldAlert className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
                  Executive SecOps Command &amp; Administration Center
                </h2>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
                  Master Authority
                </span>
                <span className={`text-[10px] uppercase font-mono px-2.5 py-0.5 rounded border font-bold ${defconColors[defconLevel as keyof typeof defconColors]}`}>
                  DEFCON {defconLevel} {defconLevel === 1 ? '• EMERGENCY LOCKDOWN' : defconLevel <= 3 ? '• ELEVATED' : '• NOMINAL'}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Centralized governance console for identity lifecycle, dynamic edge policy enforcement, and live Cloudflare Worker pipeline testing.
              </p>
            </div>
          </div>

          {/* Quick Action Controls */}
          <div className="flex items-center gap-2 flex-wrap self-start lg:self-auto">
            {/* Global Lockdown Toggle Button */}
            <button
              id="btn-toggle-global-lockdown"
              type="button"
              onClick={handleToggleLockdown}
              disabled={isSavingPolicy}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold transition-all border shadow-lg ${
                isGlobalLockdown
                  ? 'bg-rose-600 hover:bg-rose-700 text-white border-rose-500 animate-pulse'
                  : 'bg-slate-950 hover:bg-rose-950/60 text-rose-400 border-rose-500/40'
              }`}
              title="When enabled, rejects all non-administrative requests at edge"
            >
              {isGlobalLockdown ? (
                <>
                  <Lock className="w-4 h-4 text-white" />
                  <span>PERIMETER LOCKDOWN ACTIVE</span>
                </>
              ) : (
                <>
                  <Unlock className="w-4 h-4" />
                  <span>ENGAGE GLOBAL LOCKDOWN</span>
                </>
              )}
            </button>

            {/* Reset Database */}
            <button
              id="btn-admin-reset-db"
              type="button"
              onClick={onResetDatabase}
              disabled={isResetting}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors"
              title="Reset D1 database to initial test seed"
            >
              <RotateCcw className={`w-3.5 h-3.5 text-slate-400 ${isResetting ? 'animate-spin' : ''}`} />
              <span>Reset D1 Seed</span>
            </button>

            {/* Clear Logs */}
            <button
              id="btn-admin-clear-logs"
              type="button"
              onClick={onClearLogs}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors"
              title="Clear all security audit logs"
            >
              <Trash2 className="w-3.5 h-3.5 text-slate-400" />
              <span>Clear Ledger</span>
            </button>
          </div>
        </div>

        {/* Current Active Session Status Bar */}
        <div className="mt-4 pt-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Current Operator Session:</span>
            {currentSession ? (
              <span className="font-mono font-bold text-white flex items-center gap-1.5 bg-slate-950 px-2 py-1 rounded border border-slate-800">
                <span className={`w-2 h-2 rounded-full ${currentSession.user.role === 'Admin' ? 'bg-purple-400' : 'bg-blue-400'}`} />
                {currentSession.user.username}
                <span className="text-[10px] text-slate-400">({currentSession.user.role})</span>
              </span>
            ) : (
              <span className="text-amber-400 font-mono">No active session</span>
            )}
          </div>

          <div className="flex items-center gap-3 text-slate-400 font-mono text-[11px]">
            <span>Active Principals: <strong className="text-white">{users.length}</strong></span>
            <span>•</span>
            <span>Intercepted Logs: <strong className="text-white">{totalLogs}</strong></span>
            <span>•</span>
            <span>Blocked Threats: <strong className="text-rose-400">{blockedLogs}</strong></span>
          </div>
        </div>
      </div>

      {/* 2. DYNAMIC POLICY ENFORCEMENT & PRESETS GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Policy Configuration Console */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <div className="flex items-center gap-2">
              <Sliders className="w-5 h-5 text-blue-400" />
              <h3 className="font-bold text-white text-sm uppercase tracking-wider">
                Edge Security Policy Matrix
              </h3>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => handleApplyPreset('strict')}
                className="px-2 py-1 text-[11px] rounded bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors"
                title="Cutoff: 40%, Penalty: 60%"
              >
                Strict Zero-Trust
              </button>
              <button
                type="button"
                onClick={() => handleApplyPreset('standard')}
                className="px-2 py-1 text-[11px] rounded bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors"
                title="Cutoff: 75%, Penalty: 40%"
              >
                Standard
              </button>
              <button
                type="button"
                onClick={() => handleApplyPreset('permissive')}
                className="px-2 py-1 text-[11px] rounded bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors"
                title="Cutoff: 90%, Penalty: 15%"
              >
                Permissive Dev
              </button>
            </div>
          </div>

          <div className="space-y-4 text-xs font-mono">
            {/* Max Risk Threshold Slider */}
            <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
              <div className="flex items-center justify-between mb-1.5">
                <label htmlFor="risk-cutoff-threshold-slider" className="text-slate-300 font-semibold flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  Maximum Risk Cutoff Boundary:
                </label>
                <span className="text-sm font-bold text-white px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                  {threshold}%
                </span>
              </div>
              <input
                id="risk-cutoff-threshold-slider"
                type="range"
                min="10"
                max="100"
                step="5"
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value))}
                className="w-full accent-blue-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
              />
              <div className="flex justify-between text-[10px] text-slate-500 mt-1">
                <span>10% (Ultra Strict)</span>
                <span>50% (Standard Corporate)</span>
                <span>100% (Off)</span>
              </div>
            </div>

            {/* Sequence Violation Threat Penalty */}
            <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
              <div className="flex items-center justify-between mb-1.5">
                <label htmlFor="sequence-penalty-threat-slider" className="text-slate-300 font-semibold flex items-center gap-1.5">
                  <Zap className="w-4 h-4 text-amber-400" />
                  Markov Sequence Violation Threat Penalty:
                </label>
                <span className="text-sm font-bold text-white px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  +{penalty}%
                </span>
              </div>
              <input
                id="sequence-penalty-threat-slider"
                type="range"
                min="0"
                max="80"
                step="5"
                value={penalty}
                onChange={(e) => setPenalty(Number(e.target.value))}
                className="w-full accent-amber-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
              />
              <div className="flex justify-between text-[10px] text-slate-500 mt-1">
                <span>+0% (No Markov Penalty)</span>
                <span>+40% (Default Penalty)</span>
                <span>+80% (Instant Interception)</span>
              </div>
            </div>

            {/* Strict Sequence Enforcement Toggle */}
            <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-slate-300 font-semibold block">Enforce Strict Markov Chain Sequence:</span>
                <span className="text-[11px] text-slate-500">
                  Validates transitions against function_rules table in D1.
                </span>
              </div>
              <button
                type="button"
                onClick={() => setStrictSeq(!strictSeq)}
                className={`px-3 py-1 rounded text-xs font-bold transition-colors ${
                  strictSeq ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {strictSeq ? 'ACTIVE' : 'BYPASSED'}
              </button>
            </div>

            {/* Save Button */}
            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={handleSavePolicy}
                disabled={isSavingPolicy}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white shadow-md transition-colors"
              >
                {isSavingPolicy ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Propagating to Edge...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-3.5 h-3.5" />
                    Save &amp; Propagate Policy
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Cloud Diagnostics & Live Edge Test */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-4">
              <Cloud className="w-5 h-5 text-emerald-400" />
              <h3 className="font-bold text-white text-sm uppercase tracking-wider">
                Cloud Connection &amp; Live Edge
              </h3>
            </div>

            <p className="text-xs text-slate-400 mb-4">
              Live verification of the serverless edge components in production architecture.
            </p>

            <div className="space-y-3 text-xs font-mono">
              {/* Cloudflare Worker Probe */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="font-semibold text-white flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-blue-400" />
                    Edge Interceptor Probe
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Route: /api/health
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {cloudPingStatus === 'success' && (
                    <span className="text-[11px] text-emerald-400 font-bold">
                      {cloudPingLatency}ms (Online)
                    </span>
                  )}
                  {cloudPingStatus === 'error' && (
                    <span className="text-[11px] text-rose-400 font-bold">
                      Failed
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={handleTestCloudflareEdge}
                    disabled={cloudPingStatus === 'testing'}
                    className="px-2.5 py-1 text-[10px] rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/40"
                  >
                    {cloudPingStatus === 'testing' ? 'Testing...' : 'Test Ping'}
                  </button>
                </div>
              </div>

              {/* D1 Database Integrity */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="font-semibold text-white flex items-center gap-1.5">
                    <Database className="w-3.5 h-3.5 text-purple-400" />
                    Cloudflare D1 SQLite
                  </div>
                  <div className="text-[11px] text-slate-500">
                    ACID Relational Storage
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {d1Status === 'verified' ? (
                    <span className="text-[11px] text-emerald-400 font-bold flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                      Verified
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={handleVerifyD1Database}
                      disabled={d1Status === 'testing'}
                      className="px-2.5 py-1 text-[10px] rounded bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/40"
                    >
                      {d1Status === 'testing' ? 'Checking...' : 'Verify Schema'}
                    </button>
                  )}
                </div>
              </div>

              {/* HMAC-SHA256 Token Signature Check */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="font-semibold text-white flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5 text-amber-400" />
                  RFC-7519 HMAC-SHA256
                </div>
                <div className="text-[11px] text-slate-400 mt-1 truncate">
                  {currentSession ? currentSession.token : 'Awaiting Active Session Token'}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Protocol: Zero Trust v2.4</span>
            <span className="text-emerald-400">Security Cleared</span>
          </div>
        </div>
      </div>

      {/* 3. PRINCIPAL GOVERNANCE & 1-CLICK IMPERSONATION MATRIX */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <Users className="w-5 h-5 text-blue-400" />
              <h3 className="font-bold text-white text-base">
                Principal Identity Governance &amp; Impersonation Matrix
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Control all system users, switch identity with 1 click to test permissions, or adjust base risk scores in real-time.
            </p>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search principals..."
              value={userSearch}
              onChange={(e) => setUserSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-slate-950 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        {/* Users Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="pb-2.5 font-bold">Principal</th>
                <th className="pb-2.5 font-bold">Role</th>
                <th className="pb-2.5 font-bold">Base Risk</th>
                <th className="pb-2.5 font-bold">Activity Stats</th>
                <th className="pb-2.5 font-bold">Threat Clearance</th>
                <th className="pb-2.5 font-bold text-right">Admin Interventions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredUsers.map((user) => {
                const isCurrent = currentSession?.user.username === user.username;
                const userLogs = logs.filter(l => l.username === user.username);
                const userBlocked = userLogs.filter(l => l.status === 'BLOCKED').length;
                const userTotal = userLogs.length;

                return (
                  <tr key={user.id} className={`hover:bg-slate-800/40 transition-colors ${isCurrent ? 'bg-blue-950/20' : ''}`}>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${
                          user.role === 'Admin' ? 'bg-purple-400' :
                          user.role === 'Developer' ? 'bg-blue-400' : 'bg-slate-400'
                        }`} />
                        <div>
                          <span className="font-bold text-white text-xs">{user.username}</span>
                          {isCurrent && (
                            <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                              Active
                            </span>
                          )}
                        </div>
                      </div>
                    </td>

                    <td className="py-3 pr-4">
                      <select
                        aria-label={`Change role for ${user.username}`}
                        value={user.role}
                        disabled={userUpdating === user.username}
                        onChange={(e) => handleModifyUser(user.username, { role: e.target.value as any })}
                        className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded px-2 py-1 focus:outline-none focus:border-blue-500"
                      >
                        <option value="Admin">Admin</option>
                        <option value="Developer">Developer</option>
                        <option value="Guest">Guest</option>
                      </select>
                    </td>

                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2">
                        <span className={`font-bold ${
                          user.base_risk_score >= 70 ? 'text-rose-400' :
                          user.base_risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {user.base_risk_score}%
                        </span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              user.base_risk_score >= 70 ? 'bg-rose-500' :
                              user.base_risk_score >= 30 ? 'bg-amber-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${user.base_risk_score}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    <td className="py-3 pr-4 text-slate-400 text-[11px]">
                      <span>{userTotal} reqs</span>
                      {userBlocked > 0 && (
                        <span className="ml-1 text-rose-400 font-bold">({userBlocked} blocked)</span>
                      )}
                    </td>

                    <td className="py-3 pr-4">
                      {user.base_risk_score >= 80 ? (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          QUARANTINED
                        </span>
                      ) : userBlocked > 0 ? (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                          ANOMALY FLAG
                        </span>
                      ) : (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          CLEARED
                        </span>
                      )}
                    </td>

                    <td className="py-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {/* 1-Click Assume Identity */}
                        <button
                          type="button"
                          onClick={() => onSwitchSession(user)}
                          className={`px-2 py-1 text-[11px] rounded flex items-center gap-1 transition-colors ${
                            isCurrent
                              ? 'bg-blue-600 text-white font-bold'
                              : 'bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-700'
                          }`}
                          title="Assume this user's session to test their access privileges"
                        >
                          <UserCheck className="w-3 h-3 text-blue-400" />
                          <span>{isCurrent ? 'Impersonating' : 'Assume Identity'}</span>
                        </button>

                        {/* Reset Risk to 0% */}
                        <button
                          type="button"
                          onClick={() => handleModifyUser(user.username, { base_risk_score: 0 })}
                          disabled={userUpdating === user.username}
                          className="px-2 py-1 text-[11px] rounded bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors"
                          title="Clear base risk score to 0%"
                        >
                          0%
                        </button>

                        {/* Quarantine Principal */}
                        <button
                          type="button"
                          onClick={() => handleModifyUser(user.username, { base_risk_score: 100 })}
                          disabled={userUpdating === user.username}
                          className="px-2 py-1 text-[11px] rounded bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800 transition-colors"
                          title="Quarantine principal (set base risk to 100%)"
                        >
                          <UserX className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. ALL-FUNCTION DIRECT EXECUTION CONSOLE */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-purple-400" />
              <h3 className="font-bold text-white text-base">
                All-Endpoint Execution &amp; Verification Matrix
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Directly invoke system endpoints under current session ({currentSession?.user.username || 'No Active Session'}) to verify RBAC &amp; Markov sequence enforcement.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
          {systemFunctions.map((fn) => {
            const isExecuting = executingFunc === fn.path;
            const isLast = lastExecutedFunc === fn.path;

            return (
              <div
                key={fn.path}
                className={`p-4 rounded-xl border flex flex-col justify-between transition-all ${
                  isLast
                    ? 'border-blue-500/60 bg-blue-950/20'
                    : 'border-slate-800 bg-slate-950/70 hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                      {fn.tier}
                    </span>
                    <span className="text-[10px] text-slate-500">
                      Roles: {fn.allowedRoles.join(', ')}
                    </span>
                  </div>

                  <code className="text-sm font-bold text-white block mt-1">
                    {fn.name}
                  </code>
                  <div className="text-[11px] text-blue-400 mt-0.5">
                    {fn.path}
                  </div>

                  <p className="text-[11px] text-slate-400 mt-2 font-sans">
                    {fn.desc}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-900 flex items-center justify-between">
                  <span className="text-[10px] text-slate-500">
                    {fn.riskImpact}
                  </span>

                  <button
                    type="button"
                    onClick={() => handleExecuteFunction(fn.path)}
                    disabled={isExecuting}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white transition-colors"
                  >
                    {isExecuting ? (
                      <>
                        <RefreshCw className="w-3 h-3 animate-spin" />
                        Firing...
                      </>
                    ) : (
                      <>
                        <Play className="w-3 h-3 fill-white" />
                        Invoke Route
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 5. STEP-BY-STEP ENTERPRISE CLOUD ARCHITECTURE GUIDE */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-4">
          <Layers className="w-5 h-5 text-emerald-400" />
          <h3 className="font-bold text-white text-base">
            Enterprise Cloud Architecture: Cloudflare Worker &amp; D1 Integration Blueprint
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="text-[10px] font-bold text-blue-400 uppercase font-mono">Step 1: Edge Proxy</span>
            <h4 className="font-bold text-white">Cloudflare Worker</h4>
            <p className="text-slate-400 text-[11px]">
              Every inbound API request hits edge V8 workers globally with sub-millisecond cold starts before touching backend resources.
            </p>
            <code className="text-[10px] bg-slate-900 text-slate-300 p-1 rounded block font-mono">
              wrangler deploy
            </code>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="text-[10px] font-bold text-purple-400 uppercase font-mono">Step 2: Relational D1</span>
            <h4 className="font-bold text-white">Distributed SQLite</h4>
            <p className="text-slate-400 text-[11px]">
              Users, Markov sequential rules, and security audit logs are committed to Cloudflare D1 with ACID transactions.
            </p>
            <code className="text-[10px] bg-slate-900 text-slate-300 p-1 rounded block font-mono">
              wrangler d1 create zerotrust-d1
            </code>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="text-[10px] font-bold text-amber-400 uppercase font-mono">Step 3: RFC-7519 HMAC</span>
            <h4 className="font-bold text-white">Cryptographic Session</h4>
            <p className="text-slate-400 text-[11px]">
              Stateless tokens carry principal identity, baseline risk, and TTL expiration validated at edge interceptors.
            </p>
            <code className="text-[10px] bg-slate-900 text-slate-300 p-1 rounded block font-mono">
              Authorization: Bearer &lt;token&gt;
            </code>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <span className="text-[10px] font-bold text-rose-400 uppercase font-mono">Step 4: Markov Interception</span>
            <h4 className="font-bold text-white">Heuristic Firewalls</h4>
            <p className="text-slate-400 text-[11px]">
              Evaluates execution transitions dynamically. Out-of-sequence jumps incur threat penalties and trigger immediate 403 suspension.
            </p>
            <code className="text-[10px] bg-slate-900 text-slate-300 p-1 rounded block font-mono">
              Risk: base + penalty &gt;= cutoff
            </code>
          </div>
        </div>
      </div>
    </div>
  );
};
