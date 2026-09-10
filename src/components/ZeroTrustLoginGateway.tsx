import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  UserCheck,
  Users,
  Code,
  Sliders,
  Sparkles,
  ArrowRight,
  KeyRound,
  Terminal,
  Activity,
  Server,
  Fingerprint
} from 'lucide-react';
import { User, AuthSession } from '../types.ts';

interface ZeroTrustLoginGatewayProps {
  users: User[];
  onLoginSuccess: (session: AuthSession, isNewUser?: boolean) => void;
  onAddTerminalLog?: (type: 'info' | 'post' | 'get' | 'success' | 'alert' | 'error' | 'metric', text: string) => void;
}

export const ZeroTrustLoginGateway: React.FC<ZeroTrustLoginGatewayProps> = ({
  users,
  onLoginSuccess,
  onAddTerminalLog
}) => {
  const [activeTab, setActiveTab] = useState<'quick' | 'custom' | 'register'>('quick');
  const [customUsername, setCustomUsername] = useState('');
  const [customPassword, setCustomPassword] = useState('ZeroTrust_2026');
  const [registerUsername, setRegisterUsername] = useState('');
  const [registerRole, setRegisterRole] = useState<'Admin' | 'Developer' | 'Guest'>('Developer');
  const [registerRisk, setRegisterRisk] = useState(20);
  const [registerPassword, setRegisterPassword] = useState('ZeroTrust_2026');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Quick 1-Click Role Logins
  const handleQuickLogin = async (username: string, role: 'Admin' | 'Developer' | 'Guest') => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password: 'ZeroTrust_2026' })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        const user = users.find(u => u.username === username) || {
          id: data.user?.id || `usr_${username}`,
          username,
          password_hash: 'ZeroTrust_2026',
          role: data.role || role,
          base_risk_score: data.userRisk ?? (role === 'Admin' ? 0 : role === 'Developer' ? 10 : 20)
        };
        const session: AuthSession = {
          user,
          token: data.token,
          loginTime: new Date().toLocaleTimeString(),
          expiresInSeconds: data.expiresInSeconds || 3600
        };
        onLoginSuccess(session);
        onAddTerminalLog?.('success', `[IAM GATEWAY] Authenticated as ${username} with role [${user.role}].`);
      } else {
        setErrorMsg(data.error || 'Authentication failed');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Login request failed');
    } finally {
      setLoading(false);
    }
  };

  // Custom Sign In
  const handleCustomLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customUsername.trim()) return;
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: customUsername.trim(), password: customPassword })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        const existing = users.find(u => u.username.toLowerCase() === customUsername.trim().toLowerCase());
        const user: User = existing || {
          id: data.user?.id || `usr_${customUsername.trim()}`,
          username: customUsername.trim(),
          password_hash: customPassword,
          role: data.role || 'Guest',
          base_risk_score: data.userRisk ?? 20
        };
        const session: AuthSession = {
          user,
          token: data.token,
          loginTime: new Date().toLocaleTimeString(),
          expiresInSeconds: data.expiresInSeconds || 3600
        };
        onLoginSuccess(session, !existing);
        onAddTerminalLog?.('success', `[IAM GATEWAY] Authenticated as ${user.username} (${user.role}).`);
      } else {
        setErrorMsg(data.error || 'Invalid credentials or principal not recognized.');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Network error');
    } finally {
      setLoading(false);
    }
  };

  // Real-time Any User Registration
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!registerUsername.trim()) return;
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: registerUsername.trim(),
          password: registerPassword,
          role: registerRole,
          base_risk_score: registerRisk
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        const newUser: User = {
          id: data.user?.id || `usr_${Date.now()}`,
          username: registerUsername.trim(),
          password_hash: registerPassword,
          role: data.role || registerRole,
          base_risk_score: data.userRisk ?? registerRisk
        };
        const session: AuthSession = {
          user: newUser,
          token: data.token,
          loginTime: new Date().toLocaleTimeString(),
          expiresInSeconds: data.expiresInSeconds || 3600
        };
        onLoginSuccess(session, true);
        onAddTerminalLog?.('success', `[IAM GATEWAY] Dynamically provisioned and logged in as ${newUser.username} (${newUser.role}).`);
      } else {
        setErrorMsg(data.error || 'Provisioning failed');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Network error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto my-6 space-y-8 font-sans">
      {/* 1. HERO AUTHENTICATION BANNER */}
      <div className="text-center space-y-3 py-6 px-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-mono mb-2">
          <Fingerprint className="w-3.5 h-3.5" />
          <span>Zero-Trust Identity &amp; Access Gateway</span>
        </div>
        <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          Role-Gated Serverless Execution Platform
        </h2>
        <p className="text-sm text-slate-400 max-w-2xl mx-auto">
          Under strict Zero-Trust RBAC and Markov sequential isolation, features, interfaces, and cloud functions are strictly restricted to authenticated principals based on their verified role.
        </p>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 shrink-0 text-rose-400" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* 2. MODE SELECTOR TABS */}
      <div className="flex items-center justify-center gap-2 border-b border-slate-800 pb-3">
        <button
          type="button"
          onClick={() => setActiveTab('quick')}
          className={`px-4 py-2 rounded-lg text-xs font-bold transition-all border ${
            activeTab === 'quick'
              ? 'bg-blue-600 text-white border-blue-500 shadow-md'
              : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
          }`}
        >
          1-Click Role Profiles (Recommended)
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('custom')}
          className={`px-4 py-2 rounded-lg text-xs font-bold transition-all border ${
            activeTab === 'custom'
              ? 'bg-blue-600 text-white border-blue-500 shadow-md'
              : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
          }`}
        >
          Sign In Custom Principal
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('register')}
          className={`px-4 py-2 rounded-lg text-xs font-bold transition-all border ${
            activeTab === 'register'
              ? 'bg-blue-600 text-white border-blue-500 shadow-md'
              : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
          }`}
        >
          Provision New Principal
        </button>
      </div>

      {/* TAB 1: 1-CLICK ROLE DEMO CARDS */}
      {activeTab === 'quick' && (
        <div className="space-y-4">
          <div className="text-center text-xs text-slate-400 font-mono">
            Select a role profile below to immediately experience the interface tailored strictly to that role's clearance level.
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Card 1: GUEST */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg flex flex-col justify-between hover:border-emerald-500/50 transition-all group">
              <div>
                <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-bold uppercase">
                    Tier 1 Clearance
                  </span>
                  <span className="text-xs font-mono text-slate-400">Risk: 20%</span>
                </div>

                <div className="flex items-center gap-2.5 mb-2">
                  <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    <UserCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">Guest Principal</h3>
                    <code className="text-xs text-slate-400">alice_guest</code>
                  </div>
                </div>

                <div className="space-y-2 mt-4 text-xs text-slate-300">
                  <div className="text-slate-400 text-[11px] font-semibold uppercase font-mono">Permitted Views &amp; Features:</div>
                  <ul className="space-y-1.5 text-[11px] text-slate-300">
                    <li className="flex items-center gap-1.5 text-emerald-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      Guest Workspace &amp; Identity status
                    </li>
                    <li className="flex items-center gap-1.5 text-emerald-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      Invoke <code className="text-white bg-slate-950 px-1 rounded">/api/getDashboardMetrics</code>
                    </li>
                    <li className="flex items-center gap-1.5 text-emerald-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      Personal Request Audit History
                    </li>
                    <li className="flex items-center gap-1.5 text-slate-500 line-through">
                      <span>Tier 2/3 &amp; Admin Commands (Hidden)</span>
                    </li>
                  </ul>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => handleQuickLogin('alice_guest', 'Guest')}
                  disabled={loading}
                  className="w-full py-2.5 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md group-hover:shadow-emerald-600/20"
                >
                  <span>Authenticate as Guest</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Card 2: DEVELOPER */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg flex flex-col justify-between hover:border-blue-500/50 transition-all group">
              <div>
                <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30 font-bold uppercase">
                    Tier 1 &amp; 2 Clearance
                  </span>
                  <span className="text-xs font-mono text-slate-400">Risk: 10%</span>
                </div>

                <div className="flex items-center gap-2.5 mb-2">
                  <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    <Code className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">Developer Principal</h3>
                    <code className="text-xs text-slate-400">bob_developer</code>
                  </div>
                </div>

                <div className="space-y-2 mt-4 text-xs text-slate-300">
                  <div className="text-slate-400 text-[11px] font-semibold uppercase font-mono">Permitted Views &amp; Features:</div>
                  <ul className="space-y-1.5 text-[11px] text-slate-300">
                    <li className="flex items-center gap-1.5 text-blue-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                      Developer Security Interceptor
                    </li>
                    <li className="flex items-center gap-1.5 text-blue-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                      Deploy Workers &amp; View Audit Ledger
                    </li>
                    <li className="flex items-center gap-1.5 text-blue-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                      Read-Only Cloud Pipeline Review
                    </li>
                    <li className="flex items-center gap-1.5 text-slate-500 line-through">
                      <span>Executive SecOps Admin (Hidden)</span>
                    </li>
                  </ul>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => handleQuickLogin('bob_developer', 'Developer')}
                  disabled={loading}
                  className="w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md group-hover:shadow-blue-600/20"
                >
                  <span>Authenticate as Developer</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Card 3: ADMIN */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg flex flex-col justify-between hover:border-purple-500/50 transition-all group">
              <div>
                <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30 font-bold uppercase">
                    Tier 1, 2 &amp; 3 Master
                  </span>
                  <span className="text-xs font-mono text-slate-400">Risk: 0%</span>
                </div>

                <div className="flex items-center gap-2.5 mb-2">
                  <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">SecOps Admin</h3>
                    <code className="text-xs text-slate-400">secops_admin</code>
                  </div>
                </div>

                <div className="space-y-2 mt-4 text-xs text-slate-300">
                  <div className="text-slate-400 text-[11px] font-semibold uppercase font-mono">Unrestricted Master Governance:</div>
                  <ul className="space-y-1.5 text-[11px] text-slate-300">
                    <li className="flex items-center gap-1.5 text-purple-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                      Executive SecOps Command Center
                    </li>
                    <li className="flex items-center gap-1.5 text-purple-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                      Perimeter Lockdown &amp; Policy Matrix
                    </li>
                    <li className="flex items-center gap-1.5 text-purple-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                      Full IAM Provisioning &amp; User Impersonation
                    </li>
                    <li className="flex items-center gap-1.5 text-purple-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                      Markov Rule Editor &amp; KMS Key Rotation
                    </li>
                  </ul>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => handleQuickLogin('secops_admin', 'Admin')}
                  disabled={loading}
                  className="w-full py-2.5 px-4 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md group-hover:shadow-purple-600/20"
                >
                  <span>Authenticate as Admin (All Features)</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: CUSTOM SIGN IN */}
      {activeTab === 'custom' && (
        <div className="max-w-md mx-auto p-6 rounded-xl border border-slate-800 bg-slate-900/80 shadow-lg">
          <h3 className="text-base font-bold text-white mb-2 flex items-center gap-2">
            <Lock className="w-4 h-4 text-blue-400" />
            Sign In with Existing Principal
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Enter credentials for any user existing in Cloudflare D1.
          </p>

          <form onSubmit={handleCustomLogin} className="space-y-4 font-mono text-xs">
            <div>
              <label className="block text-slate-400 uppercase text-[10px] font-bold mb-1">
                Username / Handle
              </label>
              <input
                type="text"
                value={customUsername}
                onChange={(e) => setCustomUsername(e.target.value)}
                placeholder="e.g. secops_admin, bob_developer, alice_guest"
                className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-blue-500"
                required
              />
            </div>

            <div>
              <label className="block text-slate-400 uppercase text-[10px] font-bold mb-1">
                Password
              </label>
              <input
                type="password"
                value={customPassword}
                onChange={(e) => setCustomPassword(e.target.value)}
                className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-blue-500"
                required
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Default password: ZeroTrust_2026</span>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs transition-colors disabled:opacity-50"
            >
              {loading ? 'Authenticating at Edge...' : 'Sign In & Unlock Role Views'}
            </button>
          </form>
        </div>
      )}

      {/* TAB 3: REAL-TIME REGISTER */}
      {activeTab === 'register' && (
        <div className="max-w-lg mx-auto p-6 rounded-xl border border-slate-800 bg-slate-900/80 shadow-lg">
          <h3 className="text-base font-bold text-white mb-2 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-emerald-400" />
            Real-Time Dynamic Principal Provisioning
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Create any custom identity in real-time. Choose their role and base risk to test customized Zero-Trust views.
          </p>

          <form onSubmit={handleRegister} className="space-y-4 font-mono text-xs">
            <div>
              <label className="block text-slate-400 uppercase text-[10px] font-bold mb-1">
                Desired Username
              </label>
              <input
                type="text"
                value={registerUsername}
                onChange={(e) => setRegisterUsername(e.target.value)}
                placeholder="e.g. dave_intern, sec_auditor"
                className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-blue-500"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-400 uppercase text-[10px] font-bold mb-1">
                  Assign RBAC Role
                </label>
                <select
                  value={registerRole}
                  onChange={(e) => setRegisterRole(e.target.value as any)}
                  className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="Guest">Guest (Tier 1)</option>
                  <option value="Developer">Developer (Tier 1 &amp; 2)</option>
                  <option value="Admin">Admin (All Tiers)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 uppercase text-[10px] font-bold mb-1">
                  Base Risk: <span className="text-white">{registerRisk}%</span>
                </label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={registerRisk}
                  onChange={(e) => setRegisterRisk(Number(e.target.value))}
                  className="w-full accent-blue-500 mt-2"
                />
              </div>
            </div>

            <div>
              <label className="block text-slate-400 uppercase text-[10px] font-bold mb-1">
                Password
              </label>
              <input
                type="password"
                value={registerPassword}
                onChange={(e) => setRegisterPassword(e.target.value)}
                className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-blue-500"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs transition-colors disabled:opacity-50"
            >
              {loading ? 'Provisioning in D1...' : 'Provision & Sign In Instantly'}
            </button>
          </form>
        </div>
      )}

      {/* 3. ARCHITECTURAL SECURITY BADGES FOOTER */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 border-t border-slate-800/80 text-xs font-mono text-slate-400">
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center gap-2.5">
          <KeyRound className="w-4 h-4 text-blue-400 shrink-0" />
          <span>RFC-7519 HMAC-SHA256 Token Auth</span>
        </div>
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center gap-2.5">
          <Server className="w-4 h-4 text-purple-400 shrink-0" />
          <span>Cloudflare D1 Relational Users &amp; Rules</span>
        </div>
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center gap-2.5">
          <Activity className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>Per-Request Edge Interceptor Validation</span>
        </div>
      </div>
    </div>
  );
};
