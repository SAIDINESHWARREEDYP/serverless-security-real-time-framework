import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  UserCheck,
  Users,
  Code,
  ArrowRight,
  KeyRound,
  Terminal,
  Activity,
  Server,
  Fingerprint,
  Clock,
  CheckCircle2,
  XCircle,
  Building2,
  Sparkles,
  UserPlus,
  Search,
  RefreshCw
} from 'lucide-react';
import { User, AuthSession, UserApprovalStatus, MfaPendingChallenge } from '../types.ts';
import { MfaVerificationCard } from './MfaVerificationCard.tsx';

interface ZeroTrustLoginGatewayProps {
  users: User[];
  onLoginSuccess: (session: AuthSession, isNewUser?: boolean) => void;
  onAddTerminalLog?: (type: 'info' | 'post' | 'get' | 'success' | 'alert' | 'error' | 'metric', text: string) => void;
  onOpenUserDatabase?: () => void;
}

export const ZeroTrustLoginGateway: React.FC<ZeroTrustLoginGatewayProps> = ({
  users,
  onLoginSuccess,
  onAddTerminalLog,
  onOpenUserDatabase
}) => {
  const [activeTab, setActiveTab] = useState<'directory' | 'signin' | 'register' | 'quick'>('directory');
  const [customUsername, setCustomUsername] = useState('');
  const [customPassword, setCustomPassword] = useState('ZeroTrust_2026');

  // Register state
  const [registerUsername, setRegisterUsername] = useState('');
  const [registerPassword, setRegisterPassword] = useState('ZeroTrust_2026');
  const [registerRole, setRegisterRole] = useState<'Admin' | 'Developer' | 'Guest'>('Developer');
  const [registerDept, setRegisterDept] = useState('Cloud Platform Engineering');
  const [registerRisk, setRegisterRisk] = useState(20);
  const [registerJustification, setRegisterJustification] = useState('');

  // Pending approval live polling state
  const [pendingUser, setPendingUser] = useState<User | null>(null);
  const [isPollingApproval, setIsPollingApproval] = useState(false);
  const [approvalPollCount, setApprovalPollCount] = useState(0);

  // Multi-Factor Authentication Challenge state
  const [mfaChallenge, setMfaChallenge] = useState<MfaPendingChallenge | null>(null);

  // Search in directory
  const [dirSearch, setDirSearch] = useState('');

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);

  // 1. Real-time Polling for Admin Approval
  useEffect(() => {
    if (!pendingUser) {
      setIsPollingApproval(false);
      return;
    }

    setIsPollingApproval(true);
    let isCancelled = false;

    const interval = setInterval(async () => {
      try {
        setApprovalPollCount((c) => c + 1);
        const res = await fetch(`/api/auth/status?username=${encodeURIComponent(pendingUser.username)}`);
        if (!res.ok) return;
        const data = await res.json();

        if (data.success && data.approved && !isCancelled) {
          clearInterval(interval);
          setIsPollingApproval(false);
          onAddTerminalLog?.('success', `[IAM CLEARANCE] Principal ${pendingUser.username} was APPROVED by Administrator.`);

          // Complete login automatically
          const session: AuthSession = {
            user: data.user,
            token: data.token || `zt_jwt_${pendingUser.username}_${Date.now().toString(36)}`,
            loginTime: new Date().toLocaleTimeString(),
            expiresInSeconds: 3600
          };
          setPendingUser(null);
          onLoginSuccess(session);
        } else if (data.status === 'REJECTED' && !isCancelled) {
          clearInterval(interval);
          setIsPollingApproval(false);
          setErrorMsg(`Access clearance request for [${pendingUser.username}] was REJECTED by SecOps Administration.`);
          setPendingUser(null);
        }
      } catch {
        // Silent retry
      }
    }, 2500);

    return () => {
      isCancelled = true;
      clearInterval(interval);
    };
  }, [pendingUser, onLoginSuccess, onAddTerminalLog]);

  // Handle Login submission
  const executeLogin = async (username: string, password = 'ZeroTrust_2026') => {
    if (!username.trim()) return;
    setLoading(true);
    setErrorMsg(null);
    setStatusNotice(null);

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password })
      });
      const data = await res.json();

      // Case 1: Pending Admin Approval Gate
      if (data.pendingApproval || data.status === 'PENDING_APPROVAL') {
        const pUser: User = data.user || {
          id: `usr_${username}`,
          username,
          password_hash: password,
          role: data.role || 'Developer',
          base_risk_score: data.userRisk ?? 20,
          status: 'PENDING_APPROVAL'
        };
        setPendingUser(pUser);
        onAddTerminalLog?.('alert', `[IAM GATE] Login gated: Principal ${username} awaiting Administrator verification.`);
        return;
      }

      // Case 2: Rejected or Suspended
      if (res.status === 403 && (data.rejected || data.suspended)) {
        setErrorMsg(data.error || 'Access Denied: Clearance not granted for this identity.');
        return;
      }

      // Case 2.5: Multi-Factor Authentication Challenge Required
      if (data.mfaRequired && data.mfaSessionId) {
        setMfaChallenge({
          mfaSessionId: data.mfaSessionId,
          username: data.user?.username || username,
          user: data.user || {
            id: `usr_${username}`,
            username,
            password_hash: password,
            role: data.role || 'Developer',
            base_risk_score: data.userRisk ?? 15,
            status: 'APPROVED'
          },
          phoneMasked: data.phoneMasked || '+1 (555) •••-4829',
          emailMasked: data.emailMasked,
          methods: data.methods || ['authenticator', 'sms'],
          demoTotpCode: data.demoTotpCode,
          demoSmsCode: data.demoSmsCode,
          message: data.message
        });
        onAddTerminalLog?.('info', `[IAM MFA] Primary credentials verified for [${username}]. Factor 2 verification challenge required.`);
        return;
      }

      // Case 3: Direct Success (if MFA already cleared or bypassed)
      if (res.ok && data.success) {
        const user: User = data.user || {
          id: `usr_${username}`,
          username,
          password_hash: password,
          role: data.role || 'Developer',
          base_risk_score: data.userRisk ?? 15,
          status: 'APPROVED'
        };
        const session: AuthSession = {
          user,
          token: data.token,
          loginTime: new Date().toLocaleTimeString(),
          expiresInSeconds: data.expiresInSeconds || 3600
        };
        onLoginSuccess(session);
        onAddTerminalLog?.('success', `[IAM GATEWAY] Authenticated as ${user.username} [${user.role}].`);
      } else {
        setErrorMsg(data.error || 'Invalid credentials or user access denied.');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Login connection failed.');
    } finally {
      setLoading(false);
    }
  };

  // Handle Registration
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!registerUsername.trim()) return;
    setLoading(true);
    setErrorMsg(null);
    setStatusNotice(null);

    try {
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: registerUsername.trim(),
          password: registerPassword,
          role: registerRole,
          base_risk_score: registerRisk,
          department: registerDept,
          requestJustification: registerJustification || 'Self-service account registration'
        })
      });
      const data = await res.json();

      if (res.status === 409) {
        setErrorMsg(data.error || 'Username already exists. Please choose another username.');
        return;
      }

      if (res.ok && data.success) {
        if (data.pendingApproval || data.status === 'PENDING_APPROVAL') {
          setPendingUser(data.user);
          onAddTerminalLog?.('alert', `[IAM QUEUED] Principal ${data.user.username} registered. Submitted to Admin verification.`);
        } else {
          // Auto approved
          const session: AuthSession = {
            user: data.user,
            token: data.token,
            loginTime: new Date().toLocaleTimeString(),
            expiresInSeconds: data.expiresInSeconds || 3600
          };
          onLoginSuccess(session, true);
        }
      } else {
        setErrorMsg(data.error || 'Registration failed.');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Registration connection error.');
    } finally {
      setLoading(false);
    }
  };

  // Instant Simulate Approval for Testing
  const handleSimulateInstantApprove = async () => {
    if (!pendingUser) return;
    try {
      const res = await fetch('/api/system/users/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: pendingUser.username,
          approvedBy: 'secops_admin (Fast-Clear)'
        })
      });
      if (res.ok) {
        const data = await res.json();
        onAddTerminalLog?.('success', `[ADMIN] Fast-cleared identity ${pendingUser.username}.`);
        // The polling loop will catch it in ~1 sec, or we can trigger login right now:
        const session: AuthSession = {
          user: data.user,
          token: `zt_jwt_${pendingUser.username}_${Date.now().toString(36)}`,
          loginTime: new Date().toLocaleTimeString(),
          expiresInSeconds: 3600
        };
        setPendingUser(null);
        onLoginSuccess(session);
      }
    } catch {
      // Poller will catch it
    }
  };

  // Filtered users in directory
  const filteredUsers = users.filter((u) => {
    const q = dirSearch.toLowerCase().trim();
    if (!q) return true;
    return (
      u.username.toLowerCase().includes(q) ||
      (u.department && u.department.toLowerCase().includes(q)) ||
      u.role.toLowerCase().includes(q) ||
      u.status.toLowerCase().includes(q)
    );
  });

  return (
    <div className="max-w-4xl mx-auto my-6 space-y-6 font-sans">
      {/* 1. Header Banner */}
      <div className="text-center space-y-2 py-4 px-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-300 text-xs font-mono">
          <Fingerprint className="w-3.5 h-3.5 text-blue-400" />
          <span>Zero-Trust Enterprise IAM Gateway</span>
        </div>
        <h2 className="text-2xl font-bold text-white tracking-tight">
          Role-Gated Identity &amp; Verification Terminal
        </h2>
        <p className="text-xs text-slate-400 max-w-xl mx-auto">
          Every principal undergoes strict RBAC validation and administrator clearance verification before being granted system execution privileges.
        </p>
      </div>

      {/* Error / Status Notice */}
      {errorMsg && (
        <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center justify-between gap-3 animate-in fade-in">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{errorMsg}</span>
          </div>
          <button
            type="button"
            onClick={() => setErrorMsg(null)}
            className="text-rose-400 hover:text-white font-mono text-[11px]"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 2. MULTI-FACTOR AUTHENTICATION CHALLENGE SCREEN */}
      {mfaChallenge ? (
        <MfaVerificationCard
          challenge={mfaChallenge}
          onVerifySuccess={(session) => {
            setMfaChallenge(null);
            onLoginSuccess(session);
          }}
          onCancel={() => setMfaChallenge(null)}
          onAddTerminalLog={onAddTerminalLog}
          variant="page"
        />
      ) : pendingUser ? (
        <div className="p-6 rounded-2xl border border-amber-500/30 bg-slate-900/95 shadow-xl space-y-5 animate-in fade-in zoom-in-95">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
                <Clock className="w-5 h-5 animate-spin" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">
                    Administrator Verification Required
                  </h3>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold">
                    Awaiting Approval
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Your identity has been registered in the database, but access is gated until approved by SecOps Admin.
                </p>
              </div>
            </div>

            {/* Heartbeat Status Indicator */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 shrink-0">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
              <span>Live Verification Listener Active</span>
            </div>
          </div>

          {/* Pending Identity Details */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Principal Username</span>
              <span className="font-bold text-white text-sm">{pendingUser.username}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Requested Role</span>
              <span className="font-bold text-blue-400 text-sm">{pendingUser.role}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Department</span>
              <span className="text-slate-300 truncate block">{pendingUser.department || 'Engineering'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Base Risk Score</span>
              <span className="font-bold text-amber-400">{pendingUser.base_risk_score}%</span>
            </div>
          </div>

          {pendingUser.requestJustification && (
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-300">
              <span className="text-slate-500 block text-[10px] uppercase mb-1">Request Justification:</span>
              <p className="italic">"{pendingUser.requestJustification}"</p>
            </div>
          )}

          {/* Live Action Bar */}
          <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-t border-slate-800">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" />
              <span>Polling SecOps verification queue (Cycle #{approvalPollCount})...</span>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleSimulateInstantApprove}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm flex items-center gap-1.5 transition-colors"
                title="Simulate immediate SecOps Administrator approval"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Simulate Instant Admin Approval</span>
              </button>

              <button
                type="button"
                onClick={() => executeLogin('secops_admin', 'ZeroTrust_2026')}
                className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
              >
                Sign In as Admin to Review
              </button>

              <button
                type="button"
                onClick={() => setPendingUser(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      ) : (
        /* 3. NORMAL LOGIN & DIRECTORY TABS */
        <div className="rounded-2xl border border-slate-800 bg-slate-900/90 shadow-xl overflow-hidden">
          {/* Tabs */}
          <div className="flex items-center border-b border-slate-800 bg-slate-950/50 p-1.5 gap-1">
            <button
              type="button"
              onClick={() => setActiveTab('directory')}
              className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all ${
                activeTab === 'directory'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Users className="w-3.5 h-3.5 text-blue-400" />
              <span>Saved Logins Directory ({users.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('signin')}
              className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all ${
                activeTab === 'signin'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Lock className="w-3.5 h-3.5 text-purple-400" />
              <span>Sign In Credentials</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('register')}
              className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all ${
                activeTab === 'register'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <UserPlus className="w-3.5 h-3.5 text-emerald-400" />
              <span>Register New Identity</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('quick')}
              className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all ${
                activeTab === 'quick'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5 text-amber-400" />
              <span>Quick Role Profiles</span>
            </button>
          </div>

          {/* TAB 1: SAVED USER DIRECTORY */}
          {activeTab === 'directory' && (
            <div className="p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-white">
                    Saved User Database &amp; Clearances
                  </h3>
                  <p className="text-xs text-slate-400">
                    Select any approved user to log in instantly, or inspect identities awaiting admin approval.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                    <input
                      type="text"
                      value={dirSearch}
                      onChange={(e) => setDirSearch(e.target.value)}
                      placeholder="Search users..."
                      className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  {onOpenUserDatabase && (
                    <button
                      type="button"
                      onClick={onOpenUserDatabase}
                      className="px-2.5 py-1.5 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                    >
                      Manage All
                    </button>
                  )}
                </div>
              </div>

              {/* Identity Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[380px] overflow-y-auto pr-1">
                {filteredUsers.map((user) => {
                  const isApproved = user.status === 'APPROVED';
                  const isPending = user.status === 'PENDING_APPROVAL';
                  const isSuspended = user.status === 'SUSPENDED';

                  return (
                    <div
                      key={user.id || user.username}
                      className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between gap-2.5 ${
                        isApproved
                          ? 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                          : isPending
                          ? 'bg-amber-950/15 border-amber-500/30'
                          : 'bg-rose-950/15 border-rose-500/30'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <div
                            className={`w-8 h-8 rounded-lg flex items-center justify-center font-mono font-bold text-xs shrink-0 border ${
                              user.role === 'Admin'
                                ? 'bg-purple-950/40 border-purple-500/30 text-purple-300'
                                : user.role === 'Developer'
                                ? 'bg-blue-950/40 border-blue-500/30 text-blue-300'
                                : 'bg-slate-800 border-slate-700 text-slate-300'
                            }`}
                          >
                            {user.username.slice(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <div className="font-semibold text-white font-mono text-xs">
                              {user.username}
                            </div>
                            <div className="text-[11px] text-slate-400 truncate">
                              {user.department || 'Corporate Member'}
                            </div>
                          </div>
                        </div>

                        {/* Status Chip */}
                        {isApproved && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            Approved
                          </span>
                        )}
                        {isPending && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 animate-pulse font-medium">
                            Pending Gate
                          </span>
                        )}
                        {isSuspended && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30">
                            Suspended
                          </span>
                        )}
                      </div>

                      <div className="flex items-center justify-between text-[11px] pt-1 border-t border-slate-800/60 font-mono">
                        <div className="flex items-center gap-2">
                          <span className="text-slate-400">{user.role}</span>
                          <span className="text-slate-600">•</span>
                          <span
                            className={
                              user.base_risk_score >= 70
                                ? 'text-rose-400 font-bold'
                                : user.base_risk_score >= 30
                                ? 'text-amber-400 font-bold'
                                : 'text-emerald-400 font-bold'
                            }
                          >
                            {user.base_risk_score}% Risk
                          </span>
                        </div>

                        {isApproved ? (
                          <button
                            type="button"
                            disabled={loading}
                            onClick={() => executeLogin(user.username)}
                            className="px-2.5 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 font-semibold transition-colors flex items-center gap-1"
                          >
                            <span>Enter</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        ) : isPending ? (
                          <button
                            type="button"
                            onClick={() => setPendingUser(user)}
                            className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 font-semibold transition-colors"
                          >
                            Check Gate
                          </button>
                        ) : (
                          <span className="text-rose-400 font-bold">Blocked</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="pt-2 flex items-center justify-between text-xs text-slate-400 border-t border-slate-800/80">
                <span>Default Password for all seed accounts: <code className="text-blue-400">ZeroTrust_2026</code></span>
                <button
                  type="button"
                  onClick={() => setActiveTab('register')}
                  className="text-blue-400 hover:underline flex items-center gap-1"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Register a new identity</span>
                </button>
              </div>
            </div>
          )}

          {/* TAB 2: STANDARD CREDENTIALS SIGN IN */}
          {activeTab === 'signin' && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                executeLogin(customUsername, customPassword);
              }}
              className="p-6 space-y-4 max-w-md mx-auto"
            >
              <div className="text-center space-y-1 mb-2">
                <h3 className="text-sm font-semibold text-white">
                  Enter Identity Credentials
                </h3>
                <p className="text-xs text-slate-400">
                  Authenticate against the Cloudflare D1 distributed SQLite identity store.
                </p>
              </div>

              <div className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Username / Principal ID
                  </label>
                  <input
                    type="text"
                    required
                    value={customUsername}
                    onChange={(e) => setCustomUsername(e.target.value)}
                    placeholder="e.g. secops_admin, cloud_dev, alex_contractor"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Password / Access Key
                  </label>
                  <input
                    type="password"
                    required
                    value={customPassword}
                    onChange={(e) => setCustomPassword(e.target.value)}
                    placeholder="ZeroTrust_2026"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading || !customUsername.trim()}
                className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-xs transition-colors shadow-sm flex items-center justify-center gap-2 mt-2"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Verifying Identity...</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-3.5 h-3.5" />
                    <span>Authenticate &amp; Verify Clearance</span>
                  </>
                )}
              </button>

              <div className="text-center text-[11px] text-slate-500 pt-1">
                New user? Your login clearance will be validated by Administrator verification policy.
              </div>
            </form>
          )}

          {/* TAB 3: REGISTER NEW IDENTITY */}
          {activeTab === 'register' && (
            <form onSubmit={handleRegister} className="p-6 space-y-4 max-w-lg mx-auto">
              <div className="text-center space-y-1 mb-2">
                <h3 className="text-sm font-semibold text-white">
                  Register New System Identity
                </h3>
                <p className="text-xs text-slate-400">
                  New registrations are held in the Zero-Trust Gate awaiting SecOps Administrator verification.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Username *
                  </label>
                  <input
                    type="text"
                    required
                    value={registerUsername}
                    onChange={(e) => setRegisterUsername(e.target.value)}
                    placeholder="e.g. jordan_secops"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Password
                  </label>
                  <input
                    type="text"
                    value={registerPassword}
                    onChange={(e) => setRegisterPassword(e.target.value)}
                    placeholder="ZeroTrust_2026"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Requested Role
                  </label>
                  <select
                    value={registerRole}
                    onChange={(e) => setRegisterRole(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="Developer">Developer (Tier 1 &amp; Tier 2)</option>
                    <option value="Admin">Admin (Full Control)</option>
                    <option value="Guest">Guest (Tier 1 Read Only)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Department / Team
                  </label>
                  <input
                    type="text"
                    value={registerDept}
                    onChange={(e) => setRegisterDept(e.target.value)}
                    placeholder="e.g. SRE Core Platform"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div className="sm:col-span-2">
                  <label className="block text-slate-300 font-medium mb-1">
                    Access Justification (Submitted to SecOps Admin)
                  </label>
                  <input
                    type="text"
                    value={registerJustification}
                    onChange={(e) => setRegisterJustification(e.target.value)}
                    placeholder="e.g. Edge cluster telemetry validation and staging tests"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-slate-400 space-y-1">
                <div className="flex items-center gap-1.5 text-amber-400 font-medium">
                  <Clock className="w-3.5 h-3.5" />
                  <span>Zero-Trust Gate Notice</span>
                </div>
                <p>
                  Upon submission, this account will be stored in the corporate database with <code className="text-amber-300">PENDING_APPROVAL</code> status. You will enter the live verification screen until approved by SecOps.
                </p>
              </div>

              <button
                type="submit"
                disabled={loading || !registerUsername.trim()}
                className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-xs transition-colors shadow-sm flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Submitting Request...</span>
                  </>
                ) : (
                  <>
                    <UserPlus className="w-3.5 h-3.5" />
                    <span>Register &amp; Enter Verification Gate</span>
                  </>
                )}
              </button>
            </form>
          )}

          {/* TAB 4: QUICK ROLE PROFILES */}
          {activeTab === 'quick' && (
            <div className="p-6 space-y-4">
              <div className="text-center space-y-1 mb-2">
                <h3 className="text-sm font-semibold text-white">
                  1-Click Role Access Profiles
                </h3>
                <p className="text-xs text-slate-400">
                  Instantly assume pre-cleared roles to evaluate permissions, RBAC policies, and Markov chain rules.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Admin Profile */}
                <div className="p-4 rounded-xl border border-purple-500/30 bg-slate-950/70 hover:border-purple-500/50 transition-all flex flex-col justify-between gap-3">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-semibold">
                        Master Authority
                      </span>
                      <span className="text-emerald-400 font-mono text-[11px]">0% Risk</span>
                    </div>
                    <div className="font-bold text-white text-sm font-mono">secops_admin</div>
                    <p className="text-xs text-slate-400 mt-1">
                      Full access to policy tuning, emergency lockdown, cryptographic HSM, and user verification queues.
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => executeLogin('secops_admin')}
                    className="w-full py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-1.5"
                  >
                    <span>Login as Admin</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>

                {/* Developer Profile */}
                <div className="p-4 rounded-xl border border-blue-500/30 bg-slate-950/70 hover:border-blue-500/50 transition-all flex flex-col justify-between gap-3">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 font-semibold">
                        Tier 1 &amp; Tier 2
                      </span>
                      <span className="text-emerald-400 font-mono text-[11px]">15% Risk</span>
                    </div>
                    <div className="font-bold text-white text-sm font-mono">cloud_dev</div>
                    <p className="text-xs text-slate-400 mt-1">
                      Can retrieve metrics, query audit logs, and deploy edge serverless workers subject to Markov order.
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => executeLogin('cloud_dev')}
                    className="w-full py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-1.5"
                  >
                    <span>Login as Developer</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>

                {/* Auditor / Guest Profile */}
                <div className="p-4 rounded-xl border border-slate-700 bg-slate-950/70 hover:border-slate-600 transition-all flex flex-col justify-between gap-3">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-semibold">
                        Tier 1 Only
                      </span>
                      <span className="text-amber-400 font-mono text-[11px]">30% Risk</span>
                    </div>
                    <div className="font-bold text-white text-sm font-mono">auditor_guest</div>
                    <p className="text-xs text-slate-400 mt-1">
                      Limited to dashboard metrics and personal logs. Privileged function calls are rejected by edge RBAC.
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => executeLogin('auditor_guest')}
                    className="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs transition-colors flex items-center justify-center gap-1.5"
                  >
                    <span>Login as Auditor Guest</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
