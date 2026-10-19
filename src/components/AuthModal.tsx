import React, { useState } from 'react';
import {
  X,
  Key,
  ShieldCheck,
  ShieldAlert,
  Fingerprint,
  User as UserIcon,
  Copy,
  Check,
  AlertTriangle,
  CheckCircle2,
  Terminal,
  LogOut,
  Eye,
  EyeOff,
  UserPlus,
  Sliders,
  Sparkles
} from 'lucide-react';
import { User, AuthSession, MfaPendingChallenge } from '../types.ts';
import { MfaVerificationCard } from './MfaVerificationCard.tsx';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  users: User[];
  currentSession: AuthSession | null;
  onLoginSuccess: (session: AuthSession, isNewUser?: boolean) => void;
  onLogout: () => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  users,
  currentSession,
  onLoginSuccess,
  onLogout
}) => {
  const [selectedUsername, setSelectedUsername] = useState(users[0]?.username || 'secops_admin');
  const [password, setPassword] = useState('ZeroTrust_2026');
  const [showPassword, setShowPassword] = useState(false);
  const [activeTab, setActiveTab] = useState<'login' | 'custom' | 'principals' | 'token'>('login');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [mfaChallenge, setMfaChallenge] = useState<MfaPendingChallenge | null>(null);

  // Custom user registration / real-time identity state
  const [customUsername, setCustomUsername] = useState('');
  const [customRole, setCustomRole] = useState<'Admin' | 'Developer' | 'Guest'>('Developer');
  const [customRisk, setCustomRisk] = useState<number>(20);
  const [customPassword, setCustomPassword] = useState('ZeroTrust_2026');

  if (!isOpen) return null;

  const handleFormLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: selectedUsername, password })
      });
      const data = await res.json();

      if (!res.ok || !data.success) {
        setErrorMsg(data.error || 'Authentication Failed.');
        setLoading(false);
        return;
      }

      // Check for MFA Second Factor Requirement
      if (data.mfaRequired && data.mfaSessionId) {
        setMfaChallenge({
          mfaSessionId: data.mfaSessionId,
          username: data.user?.username || selectedUsername,
          user: data.user || {
            id: `usr_${selectedUsername}`,
            username: selectedUsername,
            password_hash: password,
            role: data.role || 'Developer',
            base_risk_score: data.userRisk ?? 20
          },
          phoneMasked: data.phoneMasked || '+1 (555) •••-4829',
          emailMasked: data.emailMasked,
          methods: data.methods || ['authenticator', 'sms'],
          demoTotpCode: data.demoTotpCode,
          demoSmsCode: data.demoSmsCode,
          message: data.message
        });
        setLoading(false);
        return;
      }

      const user = users.find(u => u.username === selectedUsername) || {
        id: data.user?.id || `usr_${selectedUsername}`,
        username: selectedUsername,
        password_hash: password,
        role: data.role || 'Developer',
        base_risk_score: data.userRisk ?? 20
      };

      const newSession: AuthSession = {
        user,
        token: data.token || `zt_jwt_${user.username}_${Date.now().toString(36)}`,
        loginTime: new Date().toLocaleTimeString(),
        expiresInSeconds: data.expiresInSeconds || 3600
      };

      onLoginSuccess(newSession);
      setSuccessMsg(`Authenticated successfully as ${user.username} (${user.role})!`);
      setTimeout(() => setSuccessMsg(null), 2000);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Network fault during login invocation.');
    } finally {
      setLoading(false);
    }
  };

  const handleCustomLoginOrRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customUsername.trim()) {
      setErrorMsg('Please enter a username for real-time access.');
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const cleanName = customUsername.trim().toLowerCase().replace(/\s+/g, '_');
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: cleanName,
          password: customPassword || 'ZeroTrust_2026',
          role: customRole,
          base_risk_score: Number(customRisk)
        })
      });
      const data = await res.json();

      if (!res.ok || !data.success) {
        setErrorMsg(data.error || 'Failed to initialize identity.');
        setLoading(false);
        return;
      }

      const user: User = {
        id: data.user?.id || `usr_${cleanName}`,
        username: cleanName,
        password_hash: customPassword || 'ZeroTrust_2026',
        role: customRole,
        base_risk_score: Number(customRisk),
        status: data.user?.status || 'APPROVED'
      };

      const newSession: AuthSession = {
        user,
        token: data.token || `zt_jwt_${cleanName}_${Date.now().toString(36)}`,
        loginTime: new Date().toLocaleTimeString(),
        expiresInSeconds: data.expiresInSeconds || 3600
      };

      onLoginSuccess(newSession, true);
      setSuccessMsg(`Identity provisioned & authenticated: ${cleanName} (${customRole})`);
      setTimeout(() => {
        setSuccessMsg(null);
        onClose();
      }, 1500);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Failed to authenticate custom user.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLogin = async (targetUser: User) => {
    setLoading(true);
    setErrorMsg(null);
    setSelectedUsername(targetUser.username);
    setPassword('ZeroTrust_2026');

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: targetUser.username, password: 'ZeroTrust_2026' })
      });
      const data = await res.json();
      if (data.mfaRequired && data.mfaSessionId) {
        setMfaChallenge({
          mfaSessionId: data.mfaSessionId,
          username: data.user?.username || targetUser.username,
          user: data.user || targetUser,
          phoneMasked: data.phoneMasked || '+1 (555) •••-4829',
          emailMasked: data.emailMasked,
          methods: data.methods || ['authenticator', 'sms'],
          demoTotpCode: data.demoTotpCode,
          demoSmsCode: data.demoSmsCode,
          message: data.message
        });
        setLoading(false);
        return;
      }

      if (res.ok && data.success) {
        const newSession: AuthSession = {
          user: targetUser,
          token: data.token || `zt_jwt_${targetUser.username}_${Date.now().toString(36)}`,
          loginTime: new Date().toLocaleTimeString(),
          expiresInSeconds: data.expiresInSeconds || 3600
        };
        onLoginSuccess(newSession);
        setSuccessMsg(`Session activated for ${targetUser.username}!`);
        setTimeout(() => setSuccessMsg(null), 2000);
      } else {
        setErrorMsg(data.error || 'Failed quick authorization.');
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Quick login failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyToken = () => {
    if (!currentSession?.token) return;
    navigator.clipboard.writeText(`Bearer ${currentSession.token}`);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 font-mono">
      <div className="bg-slate-950 border border-slate-800 rounded-xl shadow-2xl max-w-2xl w-full overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Fingerprint className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
                Identity & Access Management (IAM)
                <span className="text-[10px] uppercase font-normal px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                  Zero Trust Gate
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Authenticate any enterprise user in real-time and inspect cryptographic JWT tokens
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 bg-slate-950 px-4 gap-2 pt-2 overflow-x-auto">
          <button
            onClick={() => setActiveTab('login')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap ${
              activeTab === 'login'
                ? 'border-blue-500 text-blue-400 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            Standard Login
          </button>
          <button
            onClick={() => setActiveTab('custom')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap ${
              activeTab === 'custom'
                ? 'border-blue-500 text-blue-400 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <UserPlus className="w-3.5 h-3.5 text-emerald-400" />
            Real-Time Any User Access
          </button>
          <button
            onClick={() => setActiveTab('principals')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap ${
              activeTab === 'principals'
                ? 'border-blue-500 text-blue-400 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <UserIcon className="w-3.5 h-3.5" />
            Principals Roster ({users.length})
          </button>
          <button
            onClick={() => setActiveTab('token')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap ${
              activeTab === 'token'
                ? 'border-blue-500 text-blue-400 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            JWT Token Inspector
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 overflow-y-auto flex-1 space-y-4">
          {/* Feedback alerts */}
          {errorMsg && (
            <div className="p-3 bg-rose-950/50 border border-rose-500/40 text-rose-200 text-xs rounded-lg flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 bg-emerald-950/50 border border-emerald-500/40 text-emerald-200 text-xs rounded-lg flex items-center gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* MULTI-FACTOR AUTHENTICATION CHALLENGE */}
          {mfaChallenge ? (
            <MfaVerificationCard
              challenge={mfaChallenge}
              onVerifySuccess={(session) => {
                setMfaChallenge(null);
                onLoginSuccess(session);
                onClose();
              }}
              onCancel={() => setMfaChallenge(null)}
              variant="modal"
            />
          ) : (
            <>
              {/* Current Session Banner if logged in */}
              {currentSession && (
            <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></div>
                <div>
                  <div className="text-xs text-white font-bold flex items-center gap-2">
                    <span>Active Identity: {currentSession.user.username}</span>
                    <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                      currentSession.user.role === 'Admin' ? 'bg-purple-900/70 text-purple-200 border border-purple-600/40' :
                      currentSession.user.role === 'Developer' ? 'bg-blue-900/70 text-blue-200 border border-blue-600/40' :
                      'bg-slate-800 text-slate-300 border border-slate-700'
                    }`}>
                      {currentSession.user.role}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">
                    Base Risk: <span className="text-emerald-400 font-semibold">{currentSession.user.base_risk_score}%</span> | Active Since: {currentSession.loginTime}
                  </div>
                </div>
              </div>
              <button
                onClick={onLogout}
                className="px-2.5 py-1 text-xs rounded-md bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 border border-rose-800/80 flex items-center gap-1.5 transition-colors"
              >
                <LogOut className="w-3 h-3" />
                Sign Out
              </button>
            </div>
          )}

          {/* TAB 1: Direct Preset Login */}
          {activeTab === 'login' && (
            <form onSubmit={handleFormLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                  Select Enterprise Principal
                </label>
                <div className="relative">
                  <select
                    value={selectedUsername}
                    onChange={(e) => setSelectedUsername(e.target.value)}
                    className="w-full p-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-lg focus:outline-none focus:border-blue-500"
                  >
                    {users.map(u => (
                      <option key={u.id} value={u.username}>
                        {u.username} — [{u.role} | Base Risk: {u.base_risk_score}%]
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    Password / Authentication Token
                  </label>
                  <span className="text-[10px] text-blue-400">
                    Default: ZeroTrust_2026
                  </span>
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full pl-3 pr-10 py-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-lg focus:outline-none focus:border-blue-500"
                    placeholder="Enter security password"
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

              <div className="pt-2 flex items-center justify-between gap-3">
                <div className="text-[11px] text-slate-500">
                  Issues an RFC-7519 HMAC-SHA256 signature verified by Edge Interceptors.
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs flex items-center gap-2 transition-all shadow-md shadow-blue-600/20 disabled:opacity-50"
                >
                  <Key className="w-4 h-4" />
                  {loading ? 'Authenticating...' : 'Sign In & Validate'}
                </button>
              </div>
            </form>
          )}

          {/* TAB 2: Real-Time Custom User Registration / Login */}
          {activeTab === 'custom' && (
            <form onSubmit={handleCustomLoginOrRegister} className="space-y-4">
              <div className="p-3 bg-blue-950/20 border border-blue-500/30 rounded-lg text-xs text-blue-300 flex items-start gap-2.5">
                <Sparkles className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                <div>
                  <strong>Dynamic Real-Time Access:</strong> Anyone can type their own username or custom identity. The framework dynamically provisions the principal in the runtime database with your selected role and risk score!
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                  Custom Username / Identity Handle
                </label>
                <input
                  type="text"
                  value={customUsername}
                  onChange={(e) => setCustomUsername(e.target.value)}
                  placeholder="e.g. your_name, cloud_architect, sec_tester"
                  className="w-full p-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-lg focus:outline-none focus:border-blue-500 font-mono"
                  required
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                    Assigned Role
                  </label>
                  <select
                    value={customRole}
                    onChange={(e) => setCustomRole(e.target.value as any)}
                    className="w-full p-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-lg focus:outline-none focus:border-blue-500"
                  >
                    <option value="Admin">Admin (Full Access to KMS & Policy)</option>
                    <option value="Developer">Developer (Metrics, Logs, Worker Deploy)</option>
                    <option value="Guest">Guest (Read-Only Metrics)</option>
                  </select>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Base Risk Score: <span className="text-white font-bold">{customRisk}%</span>
                    </label>
                    <span className="text-[10px] text-slate-400">
                      Cutoff: 75%
                    </span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={customRisk}
                    onChange={(e) => setCustomRisk(Number(e.target.value))}
                    className="w-full accent-blue-500 cursor-pointer"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                  Password (Optional)
                </label>
                <input
                  type="password"
                  value={customPassword}
                  onChange={(e) => setCustomPassword(e.target.value)}
                  placeholder="Defaults to ZeroTrust_2026"
                  className="w-full p-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-lg focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div className="pt-2 flex items-center justify-between gap-3">
                <div className="text-[11px] text-slate-500">
                  Instant real-time registration with full audit trail logging.
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-2 transition-all shadow-md shadow-emerald-600/20 disabled:opacity-50"
                >
                  <UserPlus className="w-4 h-4" />
                  {loading ? 'Creating...' : 'Provision & Sign In'}
                </button>
              </div>
            </form>
          )}

          {/* TAB 3: Principals Roster */}
          {activeTab === 'principals' && (
            <div className="space-y-3">
              <div className="text-xs text-slate-400 mb-1">
                Select any active principal to switch contexts and evaluate RBAC boundaries:
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {users.map(u => {
                  const isCurrent = currentSession?.user.username === u.username;
                  const isUntrusted = u.base_risk_score >= 70;
                  return (
                    <div
                      key={u.id}
                      className={`p-3.5 rounded-lg border transition-all ${
                        isCurrent
                          ? 'bg-blue-950/30 border-blue-500'
                          : isUntrusted
                          ? 'bg-rose-950/20 border-rose-900/60 hover:border-rose-700/80'
                          : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="text-xs font-bold text-white flex items-center gap-2">
                            {u.username}
                            {isCurrent && (
                              <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                                Active
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-3">
                            <span>Role: <strong className="text-slate-200">{u.role}</strong></span>
                            <span>Base Risk: <strong className={u.base_risk_score >= 70 ? 'text-rose-400' : u.base_risk_score > 20 ? 'text-amber-400' : 'text-emerald-400'}>{u.base_risk_score}%</strong></span>
                          </div>
                        </div>
                        {isUntrusted ? (
                          <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />
                        ) : (
                          <ShieldCheck className="w-5 h-5 text-blue-400 shrink-0" />
                        )}
                      </div>

                      <div className="mt-3 pt-2 border-t border-slate-800 flex items-center justify-between">
                        <span className="text-[10px] text-slate-500">
                          {u.role === 'Admin' && 'Unrestricted Tier 3'}
                          {u.role === 'Developer' && 'Deploy & Logs Tier 2'}
                          {u.role === 'Guest' && !isUntrusted && 'Metrics Only Tier 1'}
                          {isUntrusted && 'Flagged Threat Profile'}
                        </span>
                        <button
                          type="button"
                          onClick={() => handleQuickLogin(u)}
                          disabled={loading}
                          className="px-2.5 py-1 text-[11px] font-semibold rounded-md bg-slate-800 hover:bg-blue-600 hover:text-white text-blue-400 transition-all border border-slate-700"
                        >
                          {isCurrent ? 'Re-Auth' : 'Switch To'}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 4: Token Inspector */}
          {activeTab === 'token' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">
                  RFC-7519 Compliant JSON Web Signature (JWS / JWT Simulation)
                </span>
                {currentSession && (
                  <button
                    onClick={handleCopyToken}
                    className="text-xs text-blue-400 hover:underline flex items-center gap-1"
                  >
                    {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedToken ? 'Copied Bearer Header!' : 'Copy Bearer Header'}
                  </button>
                )}
              </div>

              {currentSession ? (
                <div className="space-y-2">
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                    <div className="text-[10px] uppercase font-bold text-slate-500 mb-1">Decoded Header</div>
                    <pre className="text-xs text-purple-300 overflow-x-auto">
{JSON.stringify({
  alg: "HS256",
  typ: "JWT",
  kid: "kms-edge-2026-v2"
}, null, 2)}
                    </pre>
                  </div>

                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                    <div className="text-[10px] uppercase font-bold text-slate-500 mb-1">Decoded Payload Claims</div>
                    <pre className="text-xs text-blue-300 overflow-x-auto">
{JSON.stringify({
  sub: currentSession.user.username,
  role: currentSession.user.role,
  base_risk: currentSession.user.base_risk_score,
  iss: "https://auth.zerotrust.cloudflare.edge",
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + currentSession.expiresInSeconds,
  aud: "cloudflare-edge-pipeline"
}, null, 2)}
                    </pre>
                  </div>

                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between">
                    <div>
                      <div className="text-[10px] uppercase font-bold text-slate-500">Cryptographic Signature</div>
                      <div className="text-xs text-emerald-400 font-semibold mt-0.5 flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4" />
                        Signature Validated via Edge KMS Key
                      </div>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                      HS256 Verified
                    </span>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-lg text-slate-400 text-xs">
                  No active session found. Please sign in first on the "Standard Login" or "Real-Time Any User Access" tab.
                </div>
              )}
            </div>
          )}
          </>
        )}
        </div>

        {/* Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950 flex items-center justify-between text-xs text-slate-500">
          <span>Enterprise Zero-Trust Framework • Edge Security Gateway</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 transition-colors border border-slate-800"
          >
            Close Portal
          </button>
        </div>
      </div>
    </div>
  );
};
