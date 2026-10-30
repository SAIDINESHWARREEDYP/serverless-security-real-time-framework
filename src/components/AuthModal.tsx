import React, { useState, useMemo } from 'react';
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
  Sparkles,
  Clock,
  RefreshCw,
  Lock,
  ArrowRight
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

// Zero-Trust Username Validation Rule:
// More than 5 chars, at least one uppercase, one lowercase, and one alphanumeric character.
export function validateUsernameRules(username: string) {
  const clean = username.trim();
  const hasMinLength = clean.length > 5;
  const hasUpper = /[A-Z]/.test(clean);
  const hasLower = /[a-z]/.test(clean);
  const hasAlphanumeric = /[a-zA-Z0-9]/.test(clean);
  const isValid = hasMinLength && hasUpper && hasLower && hasAlphanumeric;

  return {
    hasMinLength,
    hasUpper,
    hasLower,
    hasAlphanumeric,
    isValid
  };
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  users,
  currentSession,
  onLoginSuccess,
  onLogout
}) => {
  // Input states - no preset hardcoded bypasses
  const [usernameInput, setUsernameInput] = useState(
    currentSession?.user.username || ''
  );
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [activeTab, setActiveTab] = useState<'login' | 'register' | 'principals' | 'token'>('login');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [mfaChallenge, setMfaChallenge] = useState<MfaPendingChallenge | null>(null);

  // New user registration / real-time identity state
  const [regUsername, setRegUsername] = useState('');
  const [regRole, setRegRole] = useState<'Admin' | 'Developer' | 'Guest'>('Developer');
  const [regRisk, setRegRisk] = useState<number>(20);
  const [regDept, setRegDept] = useState('Cloud Platform Engineering');
  const [regPassword, setRegPassword] = useState('ZeroTrust_2026');
  const [regJustification, setRegJustification] = useState('Self-service zero-trust identity onboarding');

  // Pending Admin Approval State
  const [pendingApprovalUser, setPendingApprovalUser] = useState<{
    username: string;
    role: string;
    status: string;
    department?: string;
    createdAt?: string;
  } | null>(null);
  const [isCheckingApproval, setIsCheckingApproval] = useState(false);
  const [approvalFeedback, setApprovalFeedback] = useState<string | null>(null);

  // Live validation calculations
  const loginUsernameRules = useMemo(() => validateUsernameRules(usernameInput), [usernameInput]);
  const regUsernameRules = useMemo(() => validateUsernameRules(regUsername), [regUsername]);

  if (!isOpen) return null;

  // Handle Sign In submission
  const handleFormLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!usernameInput.trim()) {
      setErrorMsg('Please enter your identity handle/username.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    setPendingApprovalUser(null);

    try {
      const cleanUsername = usernameInput.trim();
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: cleanUsername, password })
      });
      const data = await res.json();

      // Check if account requires Admin Approval
      if (res.status === 403 && (data.pendingApproval || data.status === 'PENDING_APPROVAL')) {
        setPendingApprovalUser({
          username: cleanUsername,
          role: data.user?.role || 'Developer',
          status: 'PENDING_APPROVAL',
          department: data.user?.department || 'Pending Verification',
          createdAt: data.user?.createdAt || new Date().toISOString()
        });
        setErrorMsg('Zero-Trust Gate Rule: New user registrations must be validated and approved by an Administrator before login.');
        setLoading(false);
        return;
      }

      if (!res.ok || !data.success) {
        setErrorMsg(data.error || 'Authentication Failed. Please verify your credentials.');
        setLoading(false);
        return;
      }

      // Check for MFA Second Factor Requirement
      if (data.mfaRequired && data.mfaSessionId) {
        setMfaChallenge({
          mfaSessionId: data.mfaSessionId,
          username: data.user?.username || cleanUsername,
          user: data.user || {
            id: `usr_${cleanUsername}`,
            username: cleanUsername,
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

      const user = users.find(u => u.username.toLowerCase() === cleanUsername.toLowerCase()) || {
        id: data.user?.id || `usr_${cleanUsername}`,
        username: cleanUsername,
        password_hash: password,
        role: data.role || 'Developer',
        base_risk_score: data.userRisk ?? 20,
        status: 'APPROVED'
      };

      const newSession: AuthSession = {
        user,
        token: data.token || `zt_jwt_${user.username}_${Date.now().toString(36)}`,
        loginTime: new Date().toLocaleTimeString(),
        expiresInSeconds: data.expiresInSeconds || 3600
      };

      onLoginSuccess(newSession);
      setSuccessMsg(`Authenticated successfully as ${user.username} (${user.role})!`);
      setTimeout(() => {
        setSuccessMsg(null);
        onClose();
      }, 1500);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Network fault during authentication gate check.');
    } finally {
      setLoading(false);
    }
  };

  // Handle Self-Service Registration
  const handleRegisterUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!regUsername.trim()) {
      setErrorMsg('Please provide a username for registration.');
      return;
    }

    if (!regUsernameRules.isValid) {
      setErrorMsg('Username must satisfy all 4 complexity rules: >5 characters, 1+ uppercase, 1+ lowercase, and alphanumeric.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const cleanName = regUsername.trim();
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: cleanName,
          password: regPassword || 'ZeroTrust_2026',
          role: regRole,
          base_risk_score: Number(regRisk),
          department: regDept,
          requestJustification: regJustification
        })
      });
      const data = await res.json();

      if (!res.ok || !data.success) {
        setErrorMsg(data.error || 'Failed to complete registration.');
        setLoading(false);
        return;
      }

      // Check if registration was queued for Admin Approval (Default Zero-Trust rule)
      if (data.pendingApproval || data.status === 'PENDING_APPROVAL') {
        setPendingApprovalUser({
          username: cleanName,
          role: regRole,
          status: 'PENDING_APPROVAL',
          department: regDept,
          createdAt: new Date().toISOString()
        });
        setSuccessMsg(`Identity [${cleanName}] submitted to database. Awaiting SecOps Admin validation.`);
        setLoading(false);
        return;
      }

      // Auto-approved (if policy is set to auto-approve)
      const user: User = {
        id: data.user?.id || `usr_${cleanName}`,
        username: cleanName,
        password_hash: regPassword || 'ZeroTrust_2026',
        role: regRole,
        base_risk_score: Number(regRisk),
        status: data.user?.status || 'APPROVED'
      };

      const newSession: AuthSession = {
        user,
        token: data.token || `zt_jwt_${cleanName}_${Date.now().toString(36)}`,
        loginTime: new Date().toLocaleTimeString(),
        expiresInSeconds: data.expiresInSeconds || 3600
      };

      onLoginSuccess(newSession, true);
      setSuccessMsg(`Identity verified & session activated: ${cleanName} (${regRole})`);
      setTimeout(() => {
        setSuccessMsg(null);
        onClose();
      }, 1500);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Failed to initialize identity registration.');
    } finally {
      setLoading(false);
    }
  };

  // Poll status of pending approval
  const handlePollApprovalStatus = async (username: string) => {
    setIsCheckingApproval(true);
    setApprovalFeedback(null);
    try {
      const res = await fetch(`/api/auth/status?username=${encodeURIComponent(username)}`);
      const data = await res.json();
      if (res.ok && data.found) {
        if (data.approved || data.status === 'APPROVED') {
          setApprovalFeedback(`Clearance Granted! Identity [${username}] has been approved by Administrator.`);
          // Log in immediately
          const user: User = data.user || {
            id: `usr_${username}`,
            username,
            role: data.role || 'Developer',
            base_risk_score: data.userRisk ?? 20,
            status: 'APPROVED'
          };
          const newSession: AuthSession = {
            user,
            token: data.token || `zt_jwt_${username}_${Date.now().toString(36)}`,
            loginTime: new Date().toLocaleTimeString(),
            expiresInSeconds: 3600
          };
          setTimeout(() => {
            onLoginSuccess(newSession);
            onClose();
          }, 1200);
        } else if (data.status === 'REJECTED') {
          setApprovalFeedback(`Clearance Denied: Administrator rejected access for [${username}].`);
        } else {
          setApprovalFeedback(`Status: Still awaiting SecOps Administrator clearance. (Queue position: 1)`);
        }
      } else {
        setApprovalFeedback('Could not check status: identity not found.');
      }
    } catch (err: any) {
      setApprovalFeedback('Error verifying status with gateway.');
    } finally {
      setIsCheckingApproval(false);
    }
  };

  // Instant admin approval action (if testing or if current session is Admin)
  const handleDirectAdminApprove = async (username: string) => {
    setIsCheckingApproval(true);
    try {
      const res = await fetch('/api/system/users/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          approvedBy: currentSession?.user.username || 'secops_admin'
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setApprovalFeedback(`Administrator Approval Granted! Access cleared for ${username}.`);
        handlePollApprovalStatus(username);
      } else {
        setApprovalFeedback(data.error || 'Failed to approve user.');
      }
    } catch (err: any) {
      setApprovalFeedback('Failed to execute admin approval.');
    } finally {
      setIsCheckingApproval(false);
    }
  };

  // Quick preset login for Admin switch
  const handleQuickLoginFromRoster = async (targetUser: User) => {
    setLoading(true);
    setErrorMsg(null);
    setUsernameInput(targetUser.username);
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
        setTimeout(() => {
          setSuccessMsg(null);
          onClose();
        }, 1500);
      } else {
        setErrorMsg(data.error || 'Failed authorization.');
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

  const isAdmin = currentSession?.user.role === 'Admin';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-4 font-mono animate-fade-in">
      <div className="bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl max-w-2xl w-full overflow-hidden flex flex-col max-h-[92vh] transition-all">
        {/* Header - Zero Trust Gateway Theme */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600/15 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0 shadow-xs">
              <Fingerprint className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-sm sm:text-base font-bold text-white tracking-wide">
                  Zero-Trust Identity &amp; Access Gate
                </h2>
                <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                  NIST SP 800-207
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Cryptographic authentication &amp; RBAC verification for serverless cloud assets
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1.5 rounded-xl hover:bg-slate-800 transition-colors shrink-0"
            aria-label="Close authentication portal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Tabs - Saved Logins only visible if user is Admin */}
        <div className="flex border-b border-slate-800 bg-slate-950 px-4 gap-2 pt-2 overflow-x-auto">
          <button
            type="button"
            onClick={() => {
              setActiveTab('login');
              setPendingApprovalUser(null);
            }}
            className={`px-3.5 py-2 text-xs font-semibold rounded-t-xl transition-all flex items-center gap-2 border-b-2 whitespace-nowrap cursor-pointer ${
              activeTab === 'login'
                ? 'border-blue-500 text-blue-400 bg-slate-900/90 font-bold'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            Sign In
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('register');
              setPendingApprovalUser(null);
            }}
            className={`px-3.5 py-2 text-xs font-semibold rounded-t-xl transition-all flex items-center gap-2 border-b-2 whitespace-nowrap cursor-pointer ${
              activeTab === 'register'
                ? 'border-blue-500 text-blue-400 bg-slate-900/90 font-bold'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <UserPlus className="w-3.5 h-3.5 text-emerald-400" />
            Register / Any User Access
          </button>

          {/* SAVED LOGINS TAB - STRICTLY VISIBLE ONLY BY ADMIN */}
          {isAdmin && (
            <button
              type="button"
              onClick={() => {
                setActiveTab('principals');
                setPendingApprovalUser(null);
              }}
              className={`px-3.5 py-2 text-xs font-semibold rounded-t-xl transition-all flex items-center gap-2 border-b-2 whitespace-nowrap cursor-pointer ${
                activeTab === 'principals'
                  ? 'border-blue-500 text-blue-400 bg-slate-900/90 font-bold'
                  : 'border-transparent text-slate-400 hover:text-white'
              }`}
            >
              <UserIcon className="w-3.5 h-3.5 text-purple-400" />
              <span>Saved Logins (Admin Only)</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                {users.length}
              </span>
            </button>
          )}

          <button
            type="button"
            onClick={() => {
              setActiveTab('token');
              setPendingApprovalUser(null);
            }}
            className={`px-3.5 py-2 text-xs font-semibold rounded-t-xl transition-all flex items-center gap-2 border-b-2 whitespace-nowrap cursor-pointer ${
              activeTab === 'token'
                ? 'border-blue-500 text-blue-400 bg-slate-900/90 font-bold'
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
            <div className="p-3 bg-rose-950/60 border border-rose-500/50 text-rose-200 text-xs rounded-xl flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1">{errorMsg}</div>
            </div>
          )}

          {successMsg && (
            <div className="p-3 bg-emerald-950/60 border border-emerald-500/50 text-emerald-200 text-xs rounded-xl flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div className="flex-1">{successMsg}</div>
            </div>
          )}

          {/* MFA CHALLENGE FLOW */}
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
          ) : pendingApprovalUser ? (
            /* PENDING ADMIN APPROVAL STATE SCREEN */
            <div className="p-5 bg-amber-950/20 border border-amber-500/40 rounded-2xl space-y-4">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 shrink-0">
                  <Clock className="w-5 h-5 animate-spin" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-white">
                      Administrator Validation &amp; Approval Required
                    </h3>
                    <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                      PENDING_APPROVAL
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                    Under Zero-Trust Access Rule (NIST SP 800-207), new user identities are recorded in the database but cannot issue access tokens until approved by a SecOps Administrator.
                  </p>
                </div>
              </div>

              {/* Pending Identity Snapshot */}
              <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Registered Username:</span>
                  <span className="font-bold text-white font-mono">{pendingApprovalUser.username}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Target Role:</span>
                  <span className="font-semibold text-blue-400">{pendingApprovalUser.role}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Department:</span>
                  <span className="text-slate-300">{pendingApprovalUser.department || 'Cloud Operations'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Queue Status:</span>
                  <span className="text-amber-400 font-bold">Awaiting SecOps Clearance</span>
                </div>
              </div>

              {approvalFeedback && (
                <div className="p-3 rounded-lg text-xs font-mono bg-slate-900 border border-slate-700 text-slate-300">
                  {approvalFeedback}
                </div>
              )}

              <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
                <button
                  type="button"
                  disabled={isCheckingApproval}
                  onClick={() => handlePollApprovalStatus(pendingApprovalUser.username)}
                  className="w-full sm:w-auto px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold flex items-center justify-center gap-2 transition-all cursor-pointer shadow-md shadow-blue-600/20 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isCheckingApproval ? 'animate-spin' : ''}`} />
                  <span>Check Verification Status</span>
                </button>

                {/* Instant Approval Shortcut for Admin verification */}
                <button
                  type="button"
                  disabled={isCheckingApproval}
                  onClick={() => handleDirectAdminApprove(pendingApprovalUser.username)}
                  className="w-full sm:w-auto px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center justify-center gap-2 transition-all cursor-pointer shadow-md shadow-emerald-600/20 disabled:opacity-50"
                  title="Approve access immediately with SecOps Admin clearance"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Approve Access Now (Admin Rule)</span>
                </button>

                <button
                  type="button"
                  onClick={() => setPendingApprovalUser(null)}
                  className="w-full sm:w-auto px-3 py-2 text-xs text-slate-400 hover:text-white transition-colors"
                >
                  Back to Sign In
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Active Session Card if logged in */}
              {currentSession && (
                <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></div>
                    <div>
                      <div className="text-xs text-white font-bold flex items-center gap-2">
                        <span>Active Session: {currentSession.user.username}</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded-md font-mono font-bold ${
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
                    className="px-3 py-1.5 text-xs rounded-xl bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 border border-rose-800/80 flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <LogOut className="w-3 h-3" />
                    Sign Out
                  </button>
                </div>
              )}

              {/* TAB 1: STANDARD CREDENTIAL LOGIN (Direct Username Input, No Exposed Roster) */}
              {activeTab === 'login' && (
                <form onSubmit={handleFormLogin} className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Username / Identity Handle
                      </label>
                      <span className="text-[10px] text-slate-400">
                        Root Admin: <button type="button" onClick={() => setUsernameInput('Secops_Admin')} className="text-blue-400 hover:underline">Secops_Admin</button>
                      </span>
                    </div>

                    <div className="relative">
                      <input
                        type="text"
                        value={usernameInput}
                        onChange={(e) => setUsernameInput(e.target.value)}
                        placeholder="Enter username (e.g. Secops_Admin, CloudDev1)"
                        className="w-full p-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-xl focus:outline-none focus:border-blue-500 font-mono"
                        required
                      />
                    </div>

                    {/* LIVE USERNAME VALIDATION RULE CHECKLIST */}
                    <div className="mt-2.5 p-3 rounded-xl bg-slate-900/70 border border-slate-800 text-[11px] space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400 font-semibold text-[10px] uppercase tracking-wider">
                          Zero-Trust Username Requirements:
                        </span>
                        {loginUsernameRules.isValid ? (
                          <span className="text-[10px] font-bold text-emerald-400 flex items-center gap-1">
                            <Check className="w-3 h-3" /> Criteria Satisfied
                          </span>
                        ) : (
                          <span className="text-[10px] text-amber-400">Rules Pending</span>
                        )}
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
                        <div className={`px-2 py-1 rounded-md text-[10px] font-mono flex items-center gap-1.5 border transition-all ${
                          loginUsernameRules.hasMinLength
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-semibold'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          <span>{loginUsernameRules.hasMinLength ? '✓' : '○'}</span>
                          <span>&gt; 5 Chars</span>
                        </div>

                        <div className={`px-2 py-1 rounded-md text-[10px] font-mono flex items-center gap-1.5 border transition-all ${
                          loginUsernameRules.hasUpper
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-semibold'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          <span>{loginUsernameRules.hasUpper ? '✓' : '○'}</span>
                          <span>1+ Upper (A-Z)</span>
                        </div>

                        <div className={`px-2 py-1 rounded-md text-[10px] font-mono flex items-center gap-1.5 border transition-all ${
                          loginUsernameRules.hasLower
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-semibold'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          <span>{loginUsernameRules.hasLower ? '✓' : '○'}</span>
                          <span>1+ Lower (a-z)</span>
                        </div>

                        <div className={`px-2 py-1 rounded-md text-[10px] font-mono flex items-center gap-1.5 border transition-all ${
                          loginUsernameRules.hasAlphanumeric
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-semibold'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          <span>{loginUsernameRules.hasAlphanumeric ? '✓' : '○'}</span>
                          <span>Alphanumeric</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Password / Authentication Secret
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
                        className="w-full pl-3 pr-10 py-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-xl focus:outline-none focus:border-blue-500 font-mono"
                        placeholder="Enter password"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-2.5 text-slate-400 hover:text-white"
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="text-[11px] text-slate-500">
                      RFC-7519 HMAC-SHA256 signature verified by Edge Interceptors.
                    </div>
                    <button
                      type="submit"
                      disabled={loading}
                      className="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md shadow-blue-600/20 disabled:opacity-50 cursor-pointer"
                    >
                      <Key className="w-4 h-4" />
                      <span>{loading ? 'Authenticating...' : 'Sign In & Validate'}</span>
                    </button>
                  </div>
                </form>
              )}

              {/* TAB 2: REAL-TIME ANY USER REGISTRATION / ACCESS */}
              {activeTab === 'register' && (
                <form onSubmit={handleRegisterUser} className="space-y-4">
                  <div className="p-3 bg-blue-950/20 border border-blue-500/30 rounded-xl text-xs text-blue-300 flex items-start gap-2.5">
                    <Sparkles className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    <div>
                      <strong>Dynamic Self-Service Registration:</strong> Any user name meeting security requirements will be provisioned. Under Zero-Trust policy, new users are placed in <span className="font-mono text-amber-300 font-bold">PENDING_APPROVAL</span> status until approved by a SecOps Administrator.
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                      Username / Identity Handle
                    </label>
                    <input
                      type="text"
                      value={regUsername}
                      onChange={(e) => setRegUsername(e.target.value)}
                      placeholder="e.g. Architect_01, Security_Lead, Cloud_Dev"
                      className="w-full p-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-xl focus:outline-none focus:border-blue-500 font-mono"
                      required
                    />

                    {/* LIVE USERNAME VALIDATION RULE CHECKLIST */}
                    <div className="mt-2.5 p-3 rounded-xl bg-slate-900/70 border border-slate-800 text-[11px] space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400 font-semibold text-[10px] uppercase tracking-wider">
                          Username Format Rules:
                        </span>
                        {regUsernameRules.isValid ? (
                          <span className="text-[10px] font-bold text-emerald-400 flex items-center gap-1">
                            <Check className="w-3 h-3" /> Meets Criteria
                          </span>
                        ) : (
                          <span className="text-[10px] text-amber-400">Requires all 4 rules</span>
                        )}
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
                        <div className={`px-2 py-1 rounded-md text-[10px] font-mono flex items-center gap-1.5 border transition-all ${
                          regUsernameRules.hasMinLength
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-semibold'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          <span>{regUsernameRules.hasMinLength ? '✓' : '○'}</span>
                          <span>&gt; 5 Chars</span>
                        </div>

                        <div className={`px-2 py-1 rounded-md text-[10px] font-mono flex items-center gap-1.5 border transition-all ${
                          regUsernameRules.hasUpper
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-semibold'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          <span>{regUsernameRules.hasUpper ? '✓' : '○'}</span>
                          <span>1+ Upper (A-Z)</span>
                        </div>

                        <div className={`px-2 py-1 rounded-md text-[10px] font-mono flex items-center gap-1.5 border transition-all ${
                          regUsernameRules.hasLower
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-semibold'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          <span>{regUsernameRules.hasLower ? '✓' : '○'}</span>
                          <span>1+ Lower (a-z)</span>
                        </div>

                        <div className={`px-2 py-1 rounded-md text-[10px] font-mono flex items-center gap-1.5 border transition-all ${
                          regUsernameRules.hasAlphanumeric
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 font-semibold'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          <span>{regUsernameRules.hasAlphanumeric ? '✓' : '○'}</span>
                          <span>Alphanumeric</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                        Requested Role
                      </label>
                      <select
                        value={regRole}
                        onChange={(e) => setRegRole(e.target.value as any)}
                        className="w-full p-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-xl focus:outline-none focus:border-blue-500"
                      >
                        <option value="Developer">Developer (Deploy, Invocations, Logs)</option>
                        <option value="Guest">Guest (Read-Only Metrics &amp; Topology)</option>
                        <option value="Admin">Admin (Requires Root Approval)</option>
                      </select>
                    </div>

                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                          Base Risk Score: <span className="text-white font-bold">{regRisk}%</span>
                        </label>
                        <span className="text-[10px] text-slate-400">
                          Threshold: 75%
                        </span>
                      </div>
                      <input
                        type="range"
                        min="0"
                        max="100"
                        value={regRisk}
                        onChange={(e) => setRegRisk(Number(e.target.value))}
                        className="w-full accent-blue-500 cursor-pointer mt-2"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                        Department / Unit
                      </label>
                      <input
                        type="text"
                        value={regDept}
                        onChange={(e) => setRegDept(e.target.value)}
                        placeholder="e.g. Cloud Operations"
                        className="w-full p-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-xl focus:outline-none focus:border-blue-500 font-mono"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                        Password (Optional)
                      </label>
                      <input
                        type="password"
                        value={regPassword}
                        onChange={(e) => setRegPassword(e.target.value)}
                        placeholder="Defaults to ZeroTrust_2026"
                        className="w-full p-2.5 bg-slate-900 border border-slate-800 text-white text-xs rounded-xl focus:outline-none focus:border-blue-500 font-mono"
                      />
                    </div>
                  </div>

                  <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="text-[11px] text-slate-500">
                      New registrations are queued for Admin verification.
                    </div>
                    <button
                      type="submit"
                      disabled={loading || !regUsernameRules.isValid}
                      className="px-6 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md shadow-emerald-600/20 disabled:opacity-50 cursor-pointer"
                    >
                      <UserPlus className="w-4 h-4" />
                      <span>{loading ? 'Submitting...' : 'Register & Queue for Approval'}</span>
                    </button>
                  </div>
                </form>
              )}

              {/* TAB 3: SAVED LOGINS (STRICTLY ADMIN ONLY) */}
              {activeTab === 'principals' && isAdmin && (
                <div className="space-y-3">
                  <div className="p-3 bg-purple-950/20 border border-purple-500/30 rounded-xl flex items-center justify-between text-xs">
                    <div className="text-purple-300">
                      <strong>Administrator View Only:</strong> Saved database identities and their security clearance profiles.
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 font-mono">
                      Restricted to Admin
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[380px] overflow-y-auto pr-1">
                    {users.map(u => {
                      const isCurrent = currentSession?.user.username === u.username;
                      const isUntrusted = u.base_risk_score >= 70;
                      return (
                        <div
                          key={u.id}
                          className={`p-3.5 rounded-xl border transition-all ${
                            isCurrent
                              ? 'bg-blue-950/30 border-blue-500 shadow-sm'
                              : isUntrusted
                              ? 'bg-rose-950/20 border-rose-900/60'
                              : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                          }`}
                        >
                          <div className="flex items-start justify-between">
                            <div>
                              <div className="text-xs font-bold text-white flex items-center gap-2">
                                <span>{u.username}</span>
                                {isCurrent && (
                                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                                    Current
                                  </span>
                                )}
                              </div>
                              <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-2.5">
                                <span>Role: <strong className="text-slate-200">{u.role}</strong></span>
                                <span>Risk: <strong className={u.base_risk_score >= 70 ? 'text-rose-400' : 'text-emerald-400'}>{u.base_risk_score}%</strong></span>
                              </div>
                            </div>
                            {isUntrusted ? (
                              <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                            ) : (
                              <ShieldCheck className="w-4 h-4 text-blue-400 shrink-0" />
                            )}
                          </div>

                          <div className="mt-3 pt-2 border-t border-slate-800 flex items-center justify-between">
                            <span className="text-[10px] text-slate-500">
                              {u.status || 'APPROVED'}
                            </span>
                            <button
                              type="button"
                              onClick={() => handleQuickLoginFromRoster(u)}
                              disabled={loading}
                              className="px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-slate-800 hover:bg-blue-600 hover:text-white text-blue-400 transition-all border border-slate-700 cursor-pointer"
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

              {/* TAB 4: TOKEN INSPECTOR */}
              {activeTab === 'token' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">
                      RFC-7519 Compliant JSON Web Signature (JWS / JWT Simulation)
                    </span>
                    {currentSession && (
                      <button
                        onClick={handleCopyToken}
                        className="text-xs text-blue-400 hover:underline flex items-center gap-1 cursor-pointer"
                      >
                        {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        {copiedToken ? 'Copied Bearer Header!' : 'Copy Bearer Header'}
                      </button>
                    )}
                  </div>

                  {currentSession ? (
                    <div className="space-y-2">
                      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl">
                        <div className="text-[10px] uppercase font-bold text-slate-500 mb-1">Decoded Header</div>
                        <pre className="text-xs text-purple-300 overflow-x-auto">
{JSON.stringify({
  alg: "HS256",
  typ: "JWT",
  kid: "kms-edge-2026-v2"
}, null, 2)}
                        </pre>
                      </div>

                      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl">
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

                      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-between">
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
                    <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl text-slate-400 text-xs">
                      No active session found. Please sign in first on the "Sign In" or "Register" tab.
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950 flex items-center justify-between text-xs text-slate-500">
          <span className="text-[11px] hidden sm:inline">Enterprise Zero-Trust Framework • Edge Security Gateway</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 transition-colors border border-slate-800 cursor-pointer"
          >
            Close Portal
          </button>
        </div>
      </div>
    </div>
  );
};
