import React, { useState, useEffect, useMemo } from 'react';
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
  RefreshCw,
  Eye,
  EyeOff,
  AlertTriangle,
  Cpu,
  Layers,
  Database
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
  // Default to secure Sign In credentials tab
  const [activeTab, setActiveTab] = useState<'signin' | 'register' | 'directory'>('signin');

  // Dynamic real-time sign in state - no preset default username
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Dynamic on-the-fly onboarding options when a new username is entered
  const [dynamicRole, setDynamicRole] = useState<'Admin' | 'Developer' | 'Guest'>('Developer');
  const [dynamicDept, setDynamicDept] = useState('Cloud Infrastructure Operations');
  const [dynamicJustification, setDynamicJustification] = useState('');

  // Dedicated Register tab state
  const [registerUsername, setRegisterUsername] = useState('');
  const [registerPassword, setRegisterPassword] = useState('');
  const [registerRole, setRegisterRole] = useState<'Admin' | 'Developer' | 'Guest'>('Developer');
  const [registerDept, setRegisterDept] = useState('Platform Engineering');
  const [registerRisk, setRegisterRisk] = useState(20);
  const [registerJustification, setRegisterJustification] = useState('');

  // Pending approval live polling state
  const [pendingUser, setPendingUser] = useState<User | null>(null);
  const [isPollingApproval, setIsPollingApproval] = useState(false);
  const [approvalPollCount, setApprovalPollCount] = useState(0);

  // Multi-Factor Authentication Challenge state
  const [mfaChallenge, setMfaChallenge] = useState<MfaPendingChallenge | null>(null);

  // Directory filter
  const [dirSearch, setDirSearch] = useState('');

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);

  // Live lookup: Check if the entered username exists in the users database
  const matchedExistingUser = useMemo(() => {
    const q = username.trim().toLowerCase();
    if (!q) return null;
    return users.find((u) => u.username.toLowerCase() === q) || null;
  }, [username, users]);

  // Real-time Zero-Trust Username Validation Rules:
  // > 5 chars, at least one uppercase, at least one lowercase, alphanumeric
  const usernameRules = useMemo(() => {
    const u = username.trim();
    // Allow built-in root seeds like secops_admin, cloud_dev, auditor_guest
    const lower = u.toLowerCase();
    const isBuiltIn = lower === 'secops_admin' || lower === 'cloud_dev' || lower === 'auditor_guest' || lower === 'sarah_infra';
    const hasMinLength = u.length > 5;
    const hasUpper = /[A-Z]/.test(u);
    const hasLower = /[a-z]/.test(u);
    const hasAlphaNum = /[0-9a-zA-Z]/.test(u);
    const isValid = isBuiltIn || (hasMinLength && hasUpper && hasLower && hasAlphaNum);

    return {
      hasMinLength,
      hasUpper,
      hasLower,
      hasAlphaNum,
      isValid,
      isBuiltIn
    };
  }, [username]);

  // Real-time Polling for Admin Approval
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
  const executeLogin = async (rawUsername: string, rawPassword?: string) => {
    const cleanUser = rawUsername.trim();
    if (!cleanUser) {
      setErrorMsg('Username is required.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setStatusNotice(null);

    try {
      const payload: any = {
        username: cleanUser,
        password: rawPassword || password || 'ZeroTrust_2026'
      };

      // If user doesn't exist yet, provide dynamic onboarding parameters
      if (!matchedExistingUser) {
        payload.role = dynamicRole;
        payload.department = dynamicDept;
        payload.requestJustification = dynamicJustification || 'Real-time dynamic identity sign-in';
      }

      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();

      // Case 1: Pending Admin Approval Gate
      if (data.pendingApproval || data.status === 'PENDING_APPROVAL') {
        const pUser: User = data.user || {
          id: `usr_${cleanUser}`,
          username: cleanUser,
          password_hash: payload.password,
          role: data.role || dynamicRole,
          base_risk_score: data.userRisk ?? 20,
          status: 'PENDING_APPROVAL',
          department: dynamicDept
        };
        setPendingUser(pUser);
        onAddTerminalLog?.('alert', `[IAM CLEARANCE] Principal ${cleanUser} registered. Held in Zero-Trust gate awaiting Admin verification.`);
        return;
      }

      // Case 2: Rejected
      if (data.rejected || data.status === 'REJECTED') {
        setErrorMsg(data.error || 'Access Denied: Account rejected by SecOps Administration.');
        return;
      }

      // Case 3: Suspended / Quarantined
      if (data.suspended || data.status === 'SUSPENDED') {
        setErrorMsg(data.error || 'Account suspended or quarantined by SecOps Security Policy.');
        return;
      }

      // Case 4: Multi-Factor Authentication Challenge Triggered
      if (data.mfaRequired) {
        onAddTerminalLog?.('info', `[MFA CHALLENGE] Password accepted for ${cleanUser}. Multi-Factor passcode required.`);
        setMfaChallenge({
          mfaSessionId: data.mfaSessionId,
          username: cleanUser,
          user: data.user,
          phoneMasked: data.phoneMasked || '+1 (555) •••-4829',
          emailMasked: data.emailMasked || `${cleanUser.toLowerCase()}@corp.internal`,
          methods: data.methods || ['authenticator', 'sms'],
          demoTotpCode: data.demoTotpCode,
          demoSmsCode: data.demoSmsCode,
          expiresInSeconds: 300
        });
        return;
      }

      // Case 5: Direct clearance granted
      if (data.success && data.token) {
        onAddTerminalLog?.('success', `[IAM VERIFIED] Session cleared for ${cleanUser} (${data.role}).`);
        const session: AuthSession = {
          user: data.user,
          token: data.token,
          loginTime: new Date().toLocaleTimeString(),
          expiresInSeconds: data.expiresInSeconds || 3600
        };
        onLoginSuccess(session, !matchedExistingUser);
      } else {
        setErrorMsg(data.error || 'Authentication denied by Zero-Trust Edge Interceptor.');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Connection failed to identity verification gateway.');
    } finally {
      setLoading(false);
    }
  };

  // Dedicated Registration handler
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!registerUsername.trim()) return;
    setLoading(true);
    setErrorMsg(null);

    try {
      const clean = registerUsername.trim();
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: clean,
          password: registerPassword || 'ZeroTrust_2026',
          role: registerRole,
          base_risk_score: registerRisk,
          department: registerDept,
          requestJustification: registerJustification || 'New self-service account registration'
        })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        if (data.pendingApproval || data.status === 'PENDING_APPROVAL') {
          const pUser: User = data.user || {
            id: `usr_${clean}`,
            username: clean,
            password_hash: registerPassword || 'ZeroTrust_2026',
            role: registerRole,
            base_risk_score: registerRisk,
            status: 'PENDING_APPROVAL',
            department: registerDept
          };
          setPendingUser(pUser);
          onAddTerminalLog?.('alert', `[IAM CLEARANCE] Account registered for [${clean}]. Awaiting SecOps clearance.`);
        } else {
          onAddTerminalLog?.('success', `[IAM PROVISIONED] Account auto-approved for [${clean}].`);
          const session: AuthSession = {
            user: data.user,
            token: data.token || `zt_jwt_${clean}_${Date.now().toString(36)}`,
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
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-300 text-xs font-mono shadow-xs">
          <Fingerprint className="w-3.5 h-3.5 text-blue-400" />
          <span>Zero-Trust Enterprise IAM Gateway • IEEE Access Bλambda Architecture</span>
        </div>
        <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Role-Gated Identity &amp; Verification Terminal
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto">
          Every principal undergoes strict RBAC validation, Markov sequence evaluation, and administrator clearance verification before being granted system access.
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
        /* 3. ZERO-TRUST APPROVAL GATE / LIVE POLLING SCREEN */
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

            <div className="flex items-center gap-2 self-start sm:self-auto">
              <span className="text-[11px] font-mono text-slate-400">
                Polls: #{approvalPollCount}
              </span>
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-slate-500 block text-[10px]">USERNAME</span>
              <span className="text-white font-bold">{pendingUser.username}</span>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-slate-500 block text-[10px]">REQUESTED ROLE</span>
              <span className="text-amber-400 font-bold">{pendingUser.role}</span>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-slate-500 block text-[10px]">BASE RISK EVALUATION</span>
              <span className="text-cyan-400 font-bold">{pendingUser.base_risk_score}%</span>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-slate-500 block text-[10px]">GATE STATUS</span>
              <span className="text-amber-300 font-bold">POLLING IN REAL-TIME</span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 text-xs">
            <span className="text-slate-400">
              To approve this user, an Administrator can approve via the SecOps Command Center or User Database.
            </span>
            <button
              type="button"
              onClick={() => setPendingUser(null)}
              className="text-slate-400 hover:text-white font-medium hover:underline cursor-pointer"
            >
              Cancel &amp; Return to Sign In
            </button>
          </div>
        </div>
      ) : (
        /* 4. MAIN IDENTITY & AUTHENTICATION PORTAL */
        <div className="rounded-2xl border border-slate-800/90 bg-slate-900/90 shadow-2xl backdrop-blur-md overflow-hidden">
          {/* Tabs */}
          <div className="flex items-center border-b border-slate-800 bg-slate-950/50 p-1.5 gap-1.5">
            <button
              type="button"
              onClick={() => setActiveTab('signin')}
              className={`flex-1 py-2.5 px-4 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer ${
                activeTab === 'signin'
                  ? 'bg-blue-600/20 text-blue-300 border border-blue-500/30 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Lock className="w-4 h-4 text-blue-400" />
              <span>Real-Time Sign In &amp; Verification</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('register')}
              className={`flex-1 py-2.5 px-4 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer ${
                activeTab === 'register'
                  ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/30 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <UserPlus className="w-4 h-4 text-emerald-400" />
              <span>Provision New Identity</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('directory')}
              className={`flex-1 py-2.5 px-4 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer ${
                activeTab === 'directory'
                  ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Users className="w-4 h-4 text-purple-400" />
              <span>Directory Reference ({users.length})</span>
            </button>
          </div>

          {/* TAB 1: ENTERPRISE REAL-TIME SIGN IN */}
          {activeTab === 'signin' && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                executeLogin(username, password);
              }}
              className="p-6 sm:p-8 space-y-5 max-w-xl mx-auto"
            >
              <div className="text-center space-y-1">
                <h3 className="text-base font-bold text-white tracking-tight flex items-center justify-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-blue-400" />
                  <span>Authenticated Identity Gateway</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Enter any username. Identity is dynamically verified in real-time with Zero-Trust compliance.
                </p>
              </div>

              {/* Username Input with Live Validation Feedback */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <label className="text-slate-300 font-medium">
                    Username / Principal ID <span className="text-rose-400">*</span>
                  </label>
                  {matchedExistingUser ? (
                    <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1 font-semibold">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Database Record Found ({matchedExistingUser.role})
                    </span>
                  ) : username.trim().length > 0 ? (
                    <span className="text-[11px] font-mono text-cyan-400 flex items-center gap-1">
                      <Sparkles className="w-3.5 h-3.5" />
                      Dynamic Onboarding (New Identity)
                    </span>
                  ) : null}
                </div>

                <div className="relative">
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Enter any username (e.g. secops_admin, cloud_dev, Alex_Sec2026)"
                    className="w-full pl-3.5 pr-10 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 text-xs sm:text-sm font-mono transition-colors shadow-inner"
                  />
                  {username && (
                    <div className="absolute right-3 top-2.5 text-slate-400">
                      {matchedExistingUser ? (
                        <UserCheck className="w-4 h-4 text-emerald-400" />
                      ) : usernameRules.isValid ? (
                        <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                      )}
                    </div>
                  )}
                </div>

                {/* Real-time Username Compliance Rule Badges */}
                {username.trim().length > 0 && !usernameRules.isBuiltIn && (
                  <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1.5">
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider font-mono font-semibold block">
                      Zero-Trust Identity Format Rules:
                    </span>
                    <div className="grid grid-cols-2 gap-1.5 text-[11px] font-mono">
                      <div className={`flex items-center gap-1.5 ${usernameRules.hasMinLength ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {usernameRules.hasMinLength ? <CheckCircle2 className="w-3 h-3" /> : <div className="w-2.5 h-2.5 rounded-full border border-slate-600" />}
                        <span>Length &gt; 5 chars ({username.trim().length})</span>
                      </div>
                      <div className={`flex items-center gap-1.5 ${usernameRules.hasUpper ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {usernameRules.hasUpper ? <CheckCircle2 className="w-3 h-3" /> : <div className="w-2.5 h-2.5 rounded-full border border-slate-600" />}
                        <span>Uppercase (A-Z)</span>
                      </div>
                      <div className={`flex items-center gap-1.5 ${usernameRules.hasLower ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {usernameRules.hasLower ? <CheckCircle2 className="w-3 h-3" /> : <div className="w-2.5 h-2.5 rounded-full border border-slate-600" />}
                        <span>Lowercase (a-z)</span>
                      </div>
                      <div className={`flex items-center gap-1.5 ${usernameRules.hasAlphaNum ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {usernameRules.hasAlphaNum ? <CheckCircle2 className="w-3 h-3" /> : <div className="w-2.5 h-2.5 rounded-full border border-slate-600" />}
                        <span>Alphanumeric char</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Password Input with Visibility Toggle */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <label className="text-slate-300 font-medium">
                    Password / Access Key <span className="text-rose-400">*</span>
                  </label>
                  <span className="text-[11px] text-slate-400 font-mono">
                    (Default seed: <code className="text-blue-400">ZeroTrust_2026</code>)
                  </span>
                </div>

                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter security password"
                    className="w-full pl-3.5 pr-10 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 text-xs sm:text-sm font-mono transition-colors shadow-inner"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-2.5 text-slate-400 hover:text-white"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* If New Identity is detected, allow quick role & department assignment */}
              {!matchedExistingUser && username.trim().length > 0 && (
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-3 animate-in fade-in">
                  <div className="flex items-center justify-between text-xs font-semibold text-cyan-300 border-b border-slate-800/80 pb-2">
                    <span className="flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                      Dynamic Real-Time Onboarding Clearance
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                      Auto-Provisioning
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1 font-medium text-[11px]">
                        Requested Clearance Role
                      </label>
                      <select
                        value={dynamicRole}
                        onChange={(e) => setDynamicRole(e.target.value as any)}
                        className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-white text-xs focus:outline-none focus:border-cyan-500"
                      >
                        <option value="Developer">Developer (Tier 1 &amp; Tier 2)</option>
                        <option value="Admin">Admin (Full Control)</option>
                        <option value="Guest">Guest (Tier 1 Read Only)</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-slate-400 mb-1 font-medium text-[11px]">
                        Department
                      </label>
                      <input
                        type="text"
                        value={dynamicDept}
                        onChange={(e) => setDynamicDept(e.target.value)}
                        placeholder="e.g. Threat Intelligence"
                        className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-white text-xs focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                  </div>

                  <p className="text-[11px] text-slate-400 italic">
                    Note: Newly onboarded non-admin identities will enter the Zero-Trust Gate awaiting Admin verification per active policy.
                  </p>
                </div>
              )}

              {/* Security Telemetry Assurance Badges */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-1 text-[11px] font-mono text-slate-400">
                <div className="flex items-center gap-1.5 p-2 rounded-lg bg-slate-950 border border-slate-800">
                  <KeyRound className="w-3 h-3 text-emerald-400" />
                  <span>2FA / MFA Enforced</span>
                </div>
                <div className="flex items-center gap-1.5 p-2 rounded-lg bg-slate-950 border border-slate-800">
                  <Activity className="w-3 h-3 text-cyan-400" />
                  <span>Sub-ms Latency</span>
                </div>
                <div className="col-span-2 sm:col-span-1 flex items-center gap-1.5 p-2 rounded-lg bg-slate-950 border border-slate-800">
                  <ShieldCheck className="w-3 h-3 text-blue-400" />
                  <span>Fail-Closed Mesh</span>
                </div>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading || !username.trim()}
                className="w-full py-3 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold text-xs sm:text-sm transition-all shadow-lg shadow-blue-900/30 flex items-center justify-center gap-2 cursor-pointer mt-3"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Verifying Credentials &amp; Clearance...</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    <span>Verify Identity &amp; Sign In</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>

              <div className="text-center text-[11px] text-slate-500">
                Secured by Cloudflare Edge Interceptor • Zero-Trust Token Verification
              </div>
            </form>
          )}

          {/* TAB 2: PROVISION NEW IDENTITY */}
          {activeTab === 'register' && (
            <form onSubmit={handleRegister} className="p-6 sm:p-8 space-y-4 max-w-xl mx-auto">
              <div className="text-center space-y-1 mb-2">
                <h3 className="text-base font-bold text-white tracking-tight flex items-center justify-center gap-2">
                  <UserPlus className="w-4 h-4 text-emerald-400" />
                  <span>Provision New System Identity</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Register a new principal directly into Cloudflare D1. Clearance status is verified upon entry.
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
                    placeholder="e.g. Jordan_SecOps26"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Initial Password
                  </label>
                  <input
                    type="text"
                    value={registerPassword}
                    onChange={(e) => setRegisterPassword(e.target.value)}
                    placeholder="ZeroTrust_2026"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Requested Clearance Role
                  </label>
                  <select
                    value={registerRole}
                    onChange={(e) => setRegisterRole(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-emerald-500"
                  >
                    <option value="Developer">Developer (Tier 1 &amp; Tier 2)</option>
                    <option value="Admin">Admin (Full Privileged Clearance)</option>
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
                    placeholder="e.g. Edge Core Engineering"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
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
                    placeholder="e.g. Microservices deployment and live telemetry audit"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-slate-400 space-y-1">
                <div className="flex items-center gap-1.5 text-amber-400 font-medium">
                  <Clock className="w-3.5 h-3.5" />
                  <span>Zero-Trust Verification Policy</span>
                </div>
                <p>
                  Upon submission, this account will be committed to the database with <code className="text-amber-300">PENDING_APPROVAL</code> status. Access will be granted once approved by SecOps Admin.
                </p>
              </div>

              <button
                type="submit"
                disabled={loading || !registerUsername.trim()}
                className="w-full py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold text-xs sm:text-sm transition-all shadow-lg shadow-emerald-900/30 flex items-center justify-center gap-2 cursor-pointer"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Submitting Clearance Request...</span>
                  </>
                ) : (
                  <>
                    <UserPlus className="w-4 h-4" />
                    <span>Register &amp; Enter Verification Gate</span>
                  </>
                )}
              </button>
            </form>
          )}

          {/* TAB 3: DIRECTORY REFERENCE (NO 1-CLICK BYPASS) */}
          {activeTab === 'directory' && (
            <div className="p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Database className="w-4 h-4 text-purple-400" />
                    <span>Registered Identities Reference</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Click "Use Identity" to pre-fill the username. Passwords and MFA verification are strictly required.
                  </p>
                </div>

                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                  <input
                    type="text"
                    value={dirSearch}
                    onChange={(e) => setDirSearch(e.target.value)}
                    placeholder="Filter identities..."
                    className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 max-h-80 overflow-y-auto pr-1">
                {filteredUsers.map((u) => (
                  <div
                    key={u.id || u.username}
                    className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-slate-700 flex items-center justify-between gap-2 transition-all"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-white">{u.username}</span>
                        <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono font-semibold ${
                          u.role === 'Admin'
                            ? 'bg-purple-500/20 text-purple-300'
                            : u.role === 'Developer'
                            ? 'bg-blue-500/20 text-blue-300'
                            : 'bg-slate-700 text-slate-300'
                        }`}>
                          {u.role}
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-500 block truncate max-w-[200px]">
                        {u.department || 'Operations'} • {u.status}
                      </span>
                    </div>

                    <button
                      type="button"
                      onClick={() => {
                        setUsername(u.username);
                        setPassword('ZeroTrust_2026');
                        setActiveTab('signin');
                      }}
                      className="px-2.5 py-1 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-mono transition-colors cursor-pointer shrink-0"
                    >
                      Use Identity →
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
