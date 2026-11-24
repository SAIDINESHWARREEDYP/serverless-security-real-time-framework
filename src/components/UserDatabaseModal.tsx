import React, { useState, useEffect, useMemo } from 'react';
import {
  Users,
  UserPlus,
  ShieldCheck,
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
  Search,
  Trash2,
  UserX,
  UserCheck,
  Building2,
  Mail,
  Key,
  Database,
  Sparkles,
  X,
  Filter,
  Download,
  Smartphone,
  KeyRound,
  AlertTriangle,
  LifeBuoy,
  Eye,
  EyeOff,
  Copy,
  Check,
  RefreshCw
} from 'lucide-react';
import { User, UserApprovalStatus } from '../types.ts';
import { getTotpRemainingSeconds } from '../utils/mfa.ts';
import { getAuthRequestHeaders } from '../utils/authTokenStore.ts';
import { useTheme } from '../context/ThemeContext.tsx';

export interface PasswordChangeRequestItem {
  id: string;
  user_id: string;
  username: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  requested_at: string;
  reviewed_at?: string;
  reviewed_by?: string;
  justification?: string;
  rejection_reason?: string;
}

export interface UsernameChangeRequestItem {
  id: string;
  user_id: string;
  current_username: string;
  requested_username: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  requested_at: string;
  reviewed_at?: string;
  reviewed_by?: string;
  justification?: string;
  rejection_reason?: string;
}

interface UserDatabaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  users: User[];
  onAddUser: (userData: {
    username: string;
    password?: string;
    role: 'Admin' | 'Developer' | 'Guest';
    base_risk_score: number;
    department?: string;
    status: UserApprovalStatus;
    requestJustification?: string;
  }) => Promise<void>;
  onApproveUser: (username: string) => Promise<void>;
  onRejectUser: (username: string, reason?: string) => Promise<void>;
  onDeleteUser: (username: string) => Promise<void>;
  onBatchSeed: () => Promise<void>;
  onRevokeSession?: (username: string) => Promise<void>;
  onSelectUserForLogin?: (user: User) => void;
  onRefreshUsers?: () => Promise<void>;
}

export const UserDatabaseModal: React.FC<UserDatabaseModalProps> = ({
  isOpen,
  onClose,
  users,
  onAddUser,
  onApproveUser,
  onRejectUser,
  onDeleteUser,
  onBatchSeed,
  onRevokeSession,
  onSelectUserForLogin,
  onRefreshUsers
}) => {
  const { isLight } = useTheme();
  const [showAddForm, setShowAddForm] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | UserApprovalStatus>('ALL');
  const [revokingUser, setRevokingUser] = useState<string | null>(null);
  const [revokedUsersList, setRevokedUsersList] = useState<Set<string>>(new Set());
  const [revocationNotice, setRevocationNotice] = useState<string | null>(null);
  const [confirmRevokeUser, setConfirmRevokeUser] = useState<User | null>(null);
  const [roleFilter, setRoleFilter] = useState<'ALL' | 'Admin' | 'Developer' | 'Guest'>('ALL');
  const [riskFilter, setRiskFilter] = useState<'ALL' | 'CRITICAL' | 'ELEVATED' | 'MODERATE' | 'NOMINAL'>('ALL');
  const [sortBy, setSortBy] = useState<'name' | 'risk_desc' | 'risk_asc' | 'status'>('name');

  // Development Mode state (facilitates troubleshooting MFA mismatches and viewing credentials)
  const [isDevMode, setIsDevMode] = useState(true);

  // Recovery Codes & MFA Reset state
  const [recoveryCodesModal, setRecoveryCodesModal] = useState<{ username: string; codes: string[] } | null>(null);
  const [isGeneratingRecovery, setIsGeneratingRecovery] = useState<string | null>(null);
  const [resettingMfaUser, setResettingMfaUser] = useState<string | null>(null);
  const [copiedCodes, setCopiedCodes] = useState(false);

  // Security Credentials View state (Metadata only — never holds raw Base32 secret)
  const [securityCredentialsUser, setSecurityCredentialsUser] = useState<{
    username: string;
    role: string;
    mfa_enabled: boolean;
    mfaConfigured: boolean;
    issuer: string;
    timeStep30s: number;
    secondsRemaining: number;
    backupCodesCount: number;
    serverTimeIso: string;
  } | null>(null);
  const [isLoadingCredentials, setIsLoadingCredentials] = useState<string | null>(null);

  // New user form state
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<'Admin' | 'Developer' | 'Guest'>('Developer');
  const [newDept, setNewDept] = useState('Engineering & Cloud Ops');
  const [newRisk, setNewRisk] = useState<number>(20);
  const [newStatus, setNewStatus] = useState<UserApprovalStatus>('APPROVED');
  const [newJustification, setNewJustification] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Credential & Identity Change Requests Management state
  const [modalTab, setModalTab] = useState<'identities' | 'pending_users' | 'password_requests'>('identities');
  const [passwordRequests, setPasswordRequests] = useState<PasswordChangeRequestItem[]>([]);
  const [usernameRequests, setUsernameRequests] = useState<UsernameChangeRequestItem[]>([]);
  const [changeRequestFilter, setChangeRequestFilter] = useState<'ALL' | 'PASSWORD' | 'USERNAME'>('ALL');
  const [isLoadingRequests, setIsLoadingRequests] = useState(false);
  const [processingRequestId, setProcessingRequestId] = useState<string | null>(null);
  const [requestNotice, setRequestNotice] = useState<string | null>(null);

  const fetchAllChangeRequests = React.useCallback(async () => {
    setIsLoadingRequests(true);
    try {
      const headers = getAuthRequestHeaders();
      const [pwdRes, usrRes] = await Promise.all([
        fetch('/api/password-requests', { headers }),
        fetch('/api/username-requests', { headers })
      ]);
      if (pwdRes.ok) {
        const data = await pwdRes.json();
        if (data.success && Array.isArray(data.requests)) {
          setPasswordRequests(data.requests);
        }
      }
      if (usrRes.ok) {
        const data = await usrRes.json();
        if (data.success && Array.isArray(data.requests)) {
          setUsernameRequests(data.requests);
        }
      }
    } catch {
      // Ignore network hiccup
    } finally {
      setIsLoadingRequests(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      fetchAllChangeRequests();
    }
  }, [isOpen, fetchAllChangeRequests]);

  const handleApprovePasswordRequest = async (id: string) => {
    setProcessingRequestId(id);
    setActionError(null);
    try {
      const res = await fetch(`/api/password-requests/${id}/approve`, {
        method: 'POST',
        headers: getAuthRequestHeaders({ 'Content-Type': 'application/json' })
      });
      const data = await res.json();
      if (data.success) {
        setRequestNotice(`Password change for [${data.username}] approved! New password saved to database.`);
        await fetchAllChangeRequests();
        onRefreshUsers?.();
      } else {
        setActionError(data.error || 'Failed to approve password change request.');
      }
    } catch (err: any) {
      setActionError(err?.message || 'Network error.');
    } finally {
      setProcessingRequestId(null);
    }
  };

  const handleRejectPasswordRequest = async (id: string) => {
    setProcessingRequestId(id);
    setActionError(null);
    try {
      const res = await fetch(`/api/password-requests/${id}/reject`, {
        method: 'POST',
        headers: getAuthRequestHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ reason: 'Declined by Administrator' })
      });
      const data = await res.json();
      if (data.success) {
        setRequestNotice(`Password change request for [${data.username}] rejected.`);
        await fetchAllChangeRequests();
      } else {
        setActionError(data.error || 'Failed to reject password change request.');
      }
    } catch (err: any) {
      setActionError(err?.message || 'Network error.');
    } finally {
      setProcessingRequestId(null);
    }
  };

  const handleApproveUsernameRequest = async (id: string) => {
    setProcessingRequestId(id);
    setActionError(null);
    try {
      const res = await fetch(`/api/username-requests/${id}/approve`, {
        method: 'POST',
        headers: getAuthRequestHeaders({ 'Content-Type': 'application/json' })
      });
      const data = await res.json();
      if (data.success) {
        setRequestNotice(`Username change from [${data.oldUsername}] to [${data.newUsername}] approved! Saved to database.`);
        await fetchAllChangeRequests();
        onRefreshUsers?.();
      } else {
        setActionError(data.error || 'Failed to approve username change request.');
      }
    } catch (err: any) {
      setActionError(err?.message || 'Network error.');
    } finally {
      setProcessingRequestId(null);
    }
  };

  const handleRejectUsernameRequest = async (id: string) => {
    setProcessingRequestId(id);
    setActionError(null);
    try {
      const res = await fetch(`/api/username-requests/${id}/reject`, {
        method: 'POST',
        headers: getAuthRequestHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ reason: 'Declined by Administrator' })
      });
      const data = await res.json();
      if (data.success) {
        setRequestNotice(`Username change request rejected.`);
        await fetchAllChangeRequests();
      } else {
        setActionError(data.error || 'Failed to reject username change request.');
      }
    } catch (err: any) {
      setActionError(err?.message || 'Network error.');
    } finally {
      setProcessingRequestId(null);
    }
  };

  const [processingApprovalUser, setProcessingApprovalUser] = useState<string | null>(null);

  const handleApprovePendingUser = async (username: string) => {
    setProcessingApprovalUser(username);
    setActionError(null);
    try {
      await onApproveUser(username);
      setRequestNotice(`Principal [${username}] has been APPROVED. Status updated in database and administrative audit log recorded.`);
      onRefreshUsers?.();
    } catch (err: any) {
      setActionError(err?.message || 'Failed to approve user.');
    } finally {
      setProcessingApprovalUser(null);
    }
  };

  const handleRejectPendingUser = async (username: string, reason?: string) => {
    setProcessingApprovalUser(username);
    setActionError(null);
    try {
      await onRejectUser(username, reason || 'Access denied by SecOps Administrator via User Database');
      setRequestNotice(`Principal [${username}] access request REJECTED. Status updated in database and administrative audit log recorded.`);
      onRefreshUsers?.();
    } catch (err: any) {
      setActionError(err?.message || 'Failed to reject user.');
    } finally {
      setProcessingApprovalUser(null);
    }
  };

  const pendingPasswordRequestsCount = passwordRequests.filter((r) => r.status === 'PENDING').length;
  const pendingUsernameRequestsCount = usernameRequests.filter((r) => r.status === 'PENDING').length;
  const totalPendingChangeRequests = pendingPasswordRequestsCount + pendingUsernameRequestsCount;

  // Live timer for TOTP 30-second synchronization window display
  useEffect(() => {
    if (!securityCredentialsUser) return;
    const interval = setInterval(() => {
      const { secondsRemaining, timeStep } = getTotpRemainingSeconds();
      setSecurityCredentialsUser((prev) =>
        prev
          ? {
              ...prev,
              timeStep30s: timeStep,
              secondsRemaining
            }
          : null
      );
    }, 1000);
    return () => clearInterval(interval);
  }, [Boolean(securityCredentialsUser)]);

  if (!isOpen) return null;

  // Handle generating single-use recovery codes
  const handleGenerateRecoveryCodes = async (targetUsername: string) => {
    setIsGeneratingRecovery(targetUsername);
    setActionError(null);
    try {
      const res = await fetch(`/api/system/users/${encodeURIComponent(targetUsername)}/recovery-codes`, {
        method: 'POST',
        headers: getAuthRequestHeaders({ 'Content-Type': 'application/json' })
      });
      const data = await res.json();
      if (data.success && Array.isArray(data.plaintextCodes)) {
        setRecoveryCodesModal({
          username: targetUsername,
          codes: data.plaintextCodes
        });
        await onRefreshUsers?.();
      } else {
        setActionError(data.error || 'Failed to generate recovery codes');
      }
    } catch (err: any) {
      setActionError(err?.message || 'Error generating recovery codes');
    } finally {
      setIsGeneratingRecovery(null);
    }
  };

  // Handle resetting first-time MFA enrollment so user can re-pair via QR at next sign-in
  const handleResetMfaEnrollment = async (targetUsername: string) => {
    setResettingMfaUser(targetUsername);
    setActionError(null);
    try {
      const res = await fetch(`/api/system/users/${encodeURIComponent(targetUsername)}/mfa-reset`, {
        method: 'POST',
        headers: getAuthRequestHeaders({ 'Content-Type': 'application/json' })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setRequestNotice(
          `MFA pairing reset for [${targetUsername}]. Next sign-in will display a fresh QR code & manual setup key.`
        );
        await onRefreshUsers?.();
      } else {
        setActionError(data.error || 'Failed to reset MFA pairing');
      }
    } catch (err: any) {
      setActionError(err?.message || 'Error resetting MFA pairing');
    } finally {
      setResettingMfaUser(null);
    }
  };

  // Handle opening Security Credentials enrollment metadata view
  const handleOpenSecurityCredentials = async (targetUser: User) => {
    setIsLoadingCredentials(targetUser.username);
    setActionError(null);
    try {
      const res = await fetch(`/api/system/users/${encodeURIComponent(targetUser.username)}/credentials`, {
        headers: getAuthRequestHeaders()
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setSecurityCredentialsUser({
          username: data.username,
          role: data.role || targetUser.role,
          mfa_enabled: Boolean(data.mfa_enabled),
          mfaConfigured: Boolean(data.mfaConfigured),
          issuer: data.issuer || 'Serverless-Sec-Framework',
          timeStep30s: data.timeStep30s ?? getTotpRemainingSeconds().timeStep,
          secondsRemaining: data.secondsRemaining ?? getTotpRemainingSeconds().secondsRemaining,
          backupCodesCount: data.backupCodesCount ?? 0,
          serverTimeIso: data.serverTimeIso || new Date().toISOString()
        });
      } else {
        setActionError(data.error || 'Failed to retrieve MFA credential metadata.');
      }
    } catch (err: any) {
      setActionError(err?.message || 'Network error retrieving MFA metadata.');
    } finally {
      setIsLoadingCredentials(null);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim()) return;
    if (!newPassword || newPassword.trim().length < 8) {
      setActionError('Password is required and must be at least 8 characters.');
      return;
    }
    setIsSubmitting(true);
    setActionError(null);
    try {
      await onAddUser({
        username: newUsername.trim(),
        password: newPassword.trim(),
        role: newRole,
        base_risk_score: newRisk,
        department: newDept,
        status: newStatus,
        requestJustification: newJustification || 'Manual creation via User Database Manager'
      });
      setNewUsername('');
      setNewPassword('');
      setNewJustification('');
      setShowAddForm(false);
    } catch (err: any) {
      setActionError(err?.message || 'Failed to save identity');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Compute Risk Distribution across users
  const userRiskStats = {
    nominal: users.filter((u) => u.base_risk_score < 25).length,
    moderate: users.filter((u) => u.base_risk_score >= 25 && u.base_risk_score < 50).length,
    elevated: users.filter((u) => u.base_risk_score >= 50 && u.base_risk_score < 75).length,
    critical: users.filter((u) => u.base_risk_score >= 75).length,
    total: users.length || 1
  };

  const filteredUsers = users
    .filter((u) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        u.username.toLowerCase().includes(q) ||
        (u.department && u.department.toLowerCase().includes(q)) ||
        u.role.toLowerCase().includes(q);

      const matchesStatus = statusFilter === 'ALL' || u.status === statusFilter;
      const matchesRole = roleFilter === 'ALL' || u.role === roleFilter;

      let matchesRisk = true;
      if (riskFilter === 'CRITICAL') matchesRisk = u.base_risk_score >= 75;
      else if (riskFilter === 'ELEVATED') matchesRisk = u.base_risk_score >= 50 && u.base_risk_score < 75;
      else if (riskFilter === 'MODERATE') matchesRisk = u.base_risk_score >= 25 && u.base_risk_score < 50;
      else if (riskFilter === 'NOMINAL') matchesRisk = u.base_risk_score < 25;

      return matchesSearch && matchesStatus && matchesRole && matchesRisk;
    })
    .sort((a, b) => {
      if (sortBy === 'risk_desc') return b.base_risk_score - a.base_risk_score;
      if (sortBy === 'risk_asc') return a.base_risk_score - b.base_risk_score;
      if (sortBy === 'status') return (a.status || '').localeCompare(b.status || '');
      return a.username.localeCompare(b.username);
    });

  const pendingUsers = useMemo(() => users.filter((u) => u.status === 'PENDING_APPROVAL'), [users]);
  const pendingCount = pendingUsers.length;
  const approvedCount = users.filter((u) => u.status === 'APPROVED').length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className={`border rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-sans ${
        isLight ? 'bg-white border-slate-200 text-slate-800' : 'bg-slate-900 border-slate-800 text-slate-200'
      }`}>
        {/* Modal Header */}
        <div className={`p-5 border-b flex items-center justify-between ${
          isLight ? 'border-slate-200 bg-slate-50/90' : 'border-slate-800 bg-slate-950/60'
        }`}>
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${
              isLight ? 'bg-blue-50 border-blue-200 text-blue-600' : 'bg-blue-500/10 border-blue-500/20 text-blue-400'
            }`}>
              <Database className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className={`text-base font-semibold tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Enterprise User Database &amp; Saved Logins
                </h3>
                <span className={`text-[11px] font-mono tabular-nums px-2 py-0.5 rounded border ${
                  isLight ? 'bg-slate-100 text-slate-700 border-slate-200' : 'bg-slate-800 text-slate-300 border-slate-700'
                }`}>
                  {users.length} Total Saved
                </span>
                {pendingCount > 0 && (
                  <span className={`text-[11px] font-mono tabular-nums px-2 py-0.5 rounded border font-semibold ${
                    isLight ? 'bg-amber-100 text-amber-800 border-amber-300' : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                  }`}>
                    {pendingCount} Pending Verification
                  </span>
                )}
              </div>
              <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                Manage registered identities, generate single-use recovery bypass codes, and inspect MFA credentials in Dev Mode.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            {/* Development Mode Toggle Switch */}
            <button
              type="button"
              onClick={() => setIsDevMode(!isDevMode)}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-semibold border flex items-center gap-1.5 transition-all cursor-pointer ${
                isDevMode
                  ? isLight
                    ? 'bg-purple-100 text-purple-800 border-purple-300 shadow-xs'
                    : 'bg-purple-600/20 text-purple-300 border-purple-500/40 shadow-xs'
                  : isLight
                  ? 'bg-white text-slate-600 border-slate-300 hover:text-slate-900'
                  : 'bg-slate-800/80 text-slate-400 border-slate-700 hover:text-white'
              }`}
              title="Toggle Development Mode to inspect Base32 secrets and troubleshoot MFA mismatches"
            >
              <Sparkles className={`w-3.5 h-3.5 ${isLight ? 'text-purple-600' : 'text-purple-400'}`} />
              <span>Dev Mode: {isDevMode ? 'ON' : 'OFF'}</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              className={`p-1.5 rounded-lg transition-colors cursor-pointer ${
                isLight ? 'text-slate-500 hover:text-slate-900 hover:bg-slate-200' : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
              title="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Real-time Session Revocation Feedback Notice */}
        {revocationNotice && (
          <div className={`px-5 py-2.5 border-b text-xs font-mono flex items-center justify-between animate-in fade-in ${
            isLight ? 'bg-rose-50 border-rose-200 text-rose-800' : 'bg-rose-500/15 border-rose-500/30 text-rose-300'
          }`}>
            <div className="flex items-center gap-2">
              <ShieldAlert className={`w-4 h-4 shrink-0 ${isLight ? 'text-rose-600' : 'text-rose-400'}`} />
              <span>{revocationNotice}</span>
            </div>
            <button
              type="button"
              onClick={() => setRevocationNotice(null)}
              className={`cursor-pointer ${isLight ? 'text-slate-500 hover:text-slate-900' : 'text-slate-400 hover:text-white'}`}
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* View Switcher: Identities vs Pending User Requests vs Credential & Identity Change Requests */}
        <div className={`px-4 py-2.5 border-b flex items-center justify-between gap-3 flex-wrap ${
          isLight ? 'border-slate-200 bg-slate-50' : 'border-slate-800 bg-slate-900/60'
        }`}>
          <div className="flex items-center gap-2 flex-wrap tabular-nums">
            <button
              type="button"
              onClick={() => setModalTab('identities')}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
                modalTab === 'identities'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-900/20'
                  : isLight
                  ? 'bg-white text-slate-600 border border-slate-200 hover:text-slate-900'
                  : 'bg-slate-800/80 text-slate-400 hover:text-white'
              }`}
            >
              <Users className="w-3.5 h-3.5" />
              <span>Registered Identities ({users.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setModalTab('pending_users')}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
                modalTab === 'pending_users'
                  ? 'bg-amber-600 text-white shadow-md shadow-amber-900/20'
                  : isLight
                  ? 'bg-white text-slate-600 border border-slate-200 hover:text-slate-900'
                  : 'bg-slate-800/80 text-slate-400 hover:text-white'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              <span>Pending Requests</span>
              {pendingCount > 0 && (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-400 text-slate-950">
                  {pendingCount} Pending
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={() => {
                setModalTab('password_requests');
                fetchAllChangeRequests();
              }}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
                modalTab === 'password_requests'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-900/20'
                  : isLight
                  ? 'bg-white text-slate-600 border border-slate-200 hover:text-slate-900'
                  : 'bg-slate-800/80 text-slate-400 hover:text-white'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Identity &amp; Credential Requests</span>
              {totalPendingChangeRequests > 0 && (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-purple-400 text-slate-950">
                  {totalPendingChangeRequests} Pending
                </span>
              )}
            </button>
          </div>

          <div className="flex items-center gap-2">
            {onRefreshUsers && (
              <button
                type="button"
                onClick={() => {
                  onRefreshUsers();
                  if (modalTab === 'password_requests') fetchAllChangeRequests();
                }}
                disabled={isLoadingRequests}
                className={`px-2.5 py-1 text-[11px] rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer ${
                  isLight
                    ? 'bg-white hover:bg-slate-100 text-slate-700 border border-slate-200'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                }`}
                title="Refresh users and requests from database"
              >
                <RefreshCw className={`w-3 h-3 ${isLoadingRequests ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            )}
          </div>
        </div>

        {/* Real-time Password Request Feedback Notice */}
        {requestNotice && (
          <div className={`px-5 py-2.5 border-b text-xs font-mono flex items-center justify-between animate-in fade-in ${
            isLight ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
          }`}>
            <div className="flex items-center gap-2">
              <CheckCircle2 className={`w-4 h-4 shrink-0 ${isLight ? 'text-emerald-600' : 'text-emerald-400'}`} />
              <span>{requestNotice}</span>
            </div>
            <button
              type="button"
              onClick={() => setRequestNotice(null)}
              className={`cursor-pointer ${isLight ? 'text-slate-500 hover:text-slate-900' : 'text-slate-400 hover:text-white'}`}
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {modalTab === 'identities' && (
          <>
            {/* Real-time Pending Approvals Alert Callout */}
            {pendingCount > 0 && (
              <div className={`mx-4 mt-3 p-3 rounded-xl border text-xs flex items-center justify-between gap-3 animate-in fade-in ${
                isLight ? 'bg-amber-50 border-amber-300 text-amber-900' : 'bg-amber-500/15 border-amber-500/40 text-amber-200'
              }`}>
                <div className="flex items-center gap-2.5">
                  <Clock className={`w-4 h-4 shrink-0 ${isLight ? 'text-amber-600' : 'text-amber-400'}`} />
                  <span>
                    <strong className="tabular-nums">{pendingCount} Identity Registration Request{pendingCount > 1 ? 's' : ''}</strong> awaiting administrator review and clearance.
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setModalTab('pending_users')}
                  className="px-2.5 py-1 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-bold text-[11px] flex items-center gap-1 transition-colors cursor-pointer shrink-0"
                >
                  <span>Review in Pending Requests</span>
                  <span>&rarr;</span>
                </button>
              </div>
            )}

            {/* Action Toolbar */}
            <div className={`p-4 border-b flex flex-col gap-3 ${
              isLight ? 'border-slate-200 bg-slate-50/70' : 'border-slate-800/80 bg-slate-900/40'
            }`}>
          {/* Top Risk Visual Spectrum Bar */}
          <div className={`p-2.5 border rounded-xl tabular-nums ${
            isLight ? 'bg-white border-slate-200' : 'bg-slate-950/80 border-slate-800/80'
          }`}>
            <div className="flex items-center justify-between text-[11px] mb-1.5">
              <span className={`font-semibold flex items-center gap-1.5 ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>
                <ShieldCheck className={`w-3.5 h-3.5 ${isLight ? 'text-blue-600' : 'text-blue-400'}`} />
                Identity Risk Spectrum Distribution
              </span>
              <span className="text-slate-500 text-[10px]">{users.length} Registered Identities</span>
            </div>
            <div className={`h-2 w-full rounded-full overflow-hidden flex border ${
              isLight ? 'bg-slate-100 border-slate-200' : 'bg-slate-900 border-slate-800'
            }`}>
              <div
                style={{ width: `${Math.round((userRiskStats.nominal / userRiskStats.total) * 100)}%` }}
                className="bg-emerald-500 transition-all"
                title={`Nominal (<25%): ${userRiskStats.nominal}`}
              />
              <div
                style={{ width: `${Math.round((userRiskStats.moderate / userRiskStats.total) * 100)}%` }}
                className="bg-cyan-500 transition-all"
                title={`Moderate (25-49%): ${userRiskStats.moderate}`}
              />
              <div
                style={{ width: `${Math.round((userRiskStats.elevated / userRiskStats.total) * 100)}%` }}
                className="bg-amber-400 transition-all"
                title={`Elevated (50-74%): ${userRiskStats.elevated}`}
              />
              <div
                style={{ width: `${Math.round((userRiskStats.critical / userRiskStats.total) * 100)}%` }}
                className="bg-rose-500 transition-all"
                title={`Critical (≥75%): ${userRiskStats.critical}`}
              />
            </div>
            <div className={`flex items-center gap-3 mt-2 text-[10px] flex-wrap ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              <button
                type="button"
                onClick={() => setRiskFilter(riskFilter === 'NOMINAL' ? 'ALL' : 'NOMINAL')}
                className={`flex items-center gap-1 transition-colors cursor-pointer ${
                  riskFilter === 'NOMINAL'
                    ? isLight ? 'text-emerald-700 font-bold' : 'text-emerald-300 font-bold'
                    : isLight ? 'hover:text-slate-900' : 'hover:text-white'
                }`}
              >
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                Nominal: {userRiskStats.nominal}
              </button>
              <button
                type="button"
                onClick={() => setRiskFilter(riskFilter === 'MODERATE' ? 'ALL' : 'MODERATE')}
                className={`flex items-center gap-1 transition-colors cursor-pointer ${
                  riskFilter === 'MODERATE'
                    ? isLight ? 'text-cyan-700 font-bold' : 'text-cyan-300 font-bold'
                    : isLight ? 'hover:text-slate-900' : 'hover:text-white'
                }`}
              >
                <span className="w-2 h-2 rounded-full bg-cyan-500" />
                Moderate: {userRiskStats.moderate}
              </button>
              <button
                type="button"
                onClick={() => setRiskFilter(riskFilter === 'ELEVATED' ? 'ALL' : 'ELEVATED')}
                className={`flex items-center gap-1 transition-colors cursor-pointer ${
                  riskFilter === 'ELEVATED'
                    ? isLight ? 'text-amber-700 font-bold' : 'text-amber-300 font-bold'
                    : isLight ? 'hover:text-slate-900' : 'hover:text-white'
                }`}
              >
                <span className="w-2 h-2 rounded-full bg-amber-400" />
                Elevated: {userRiskStats.elevated}
              </button>
              <button
                type="button"
                onClick={() => setRiskFilter(riskFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
                className={`flex items-center gap-1 transition-colors cursor-pointer ${
                  riskFilter === 'CRITICAL'
                    ? isLight ? 'text-rose-700 font-bold' : 'text-rose-300 font-bold'
                    : isLight ? 'hover:text-slate-900' : 'hover:text-white'
                }`}
              >
                <span className="w-2 h-2 rounded-full bg-rose-500" />
                Critical: {userRiskStats.critical}
              </button>
              {riskFilter !== 'ALL' && (
                <button
                  type="button"
                  onClick={() => setRiskFilter('ALL')}
                  className="text-blue-500 hover:underline text-[10px] ml-auto cursor-pointer"
                >
                  Clear Risk Filter
                </button>
              )}
            </div>
          </div>

          {/* Search, Status, Role, Risk, and Sort Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2.5">
            <div className="flex items-center gap-2 flex-1 min-w-[240px] flex-wrap sm:flex-nowrap">
              <div className="relative flex-1 min-w-[180px]">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search username, department, or role..."
                  className={`w-full pl-8 pr-3 py-1.5 text-xs border rounded-lg focus:outline-none focus:border-blue-500/50 ${
                    isLight ? 'bg-white border-slate-300 text-slate-900 placeholder-slate-400' : 'bg-slate-950 border-slate-800 text-white placeholder-slate-500'
                  }`}
                />
              </div>

              {/* Status Filter */}
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as any)}
                className={`border text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500 ${
                  isLight ? 'bg-white border-slate-300 text-slate-700' : 'bg-slate-950 border-slate-800 text-slate-300'
                }`}
              >
                <option value="ALL">All Statuses</option>
                <option value="APPROVED">Approved ({approvedCount})</option>
                <option value="PENDING_APPROVAL">Pending Approval ({pendingCount})</option>
                <option value="REJECTED">Rejected</option>
                <option value="SUSPENDED">Suspended</option>
              </select>

              {/* Role Filter */}
              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value as any)}
                className={`border text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500 ${
                  isLight ? 'bg-white border-slate-300 text-slate-700' : 'bg-slate-950 border-slate-800 text-slate-300'
                }`}
              >
                <option value="ALL">All Roles</option>
                <option value="Admin">Admin</option>
                <option value="Developer">Developer</option>
                <option value="Guest">Guest</option>
              </select>

              {/* Risk Level Filter */}
              <select
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value as any)}
                className={`border text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500 ${
                  isLight ? 'bg-white border-slate-300 text-slate-700' : 'bg-slate-950 border-slate-800 text-slate-300'
                }`}
              >
                <option value="ALL">All Risk Levels</option>
                <option value="NOMINAL">Nominal (&lt;25%)</option>
                <option value="MODERATE">Moderate (25-49%)</option>
                <option value="ELEVATED">Elevated (50-74%)</option>
                <option value="CRITICAL">Critical (≥75%)</option>
              </select>

              {/* Sort By Dropdown */}
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className={`border text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500 ${
                  isLight ? 'bg-white border-slate-300 text-slate-700' : 'bg-slate-950 border-slate-800 text-slate-300'
                }`}
              >
                <option value="name">Sort: Name (A-Z)</option>
                <option value="risk_desc">Sort: Highest Risk</option>
                <option value="risk_asc">Sort: Lowest Risk</option>
                <option value="status">Sort: Status</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => onBatchSeed()}
                className={`px-3 py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer ${
                  isLight ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300' : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                }`}
                title="Populate test corporate users in database"
              >
                <Sparkles className={`w-3.5 h-3.5 ${isLight ? 'text-amber-600' : 'text-amber-400'}`} />
                <span>Seed Enterprise Users</span>
              </button>

              <button
                type="button"
                onClick={() => setShowAddForm(!showAddForm)}
                className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors cursor-pointer"
              >
                <UserPlus className="w-3.5 h-3.5" />
                <span>{showAddForm ? 'Hide Form' : 'Save New User Login'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Add User Drawer Form */}
        {showAddForm && (
          <form
            onSubmit={handleCreateUser}
            className={`p-4 border-b animate-in slide-in-from-top-2 duration-150 ${
              isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/80 border-slate-800'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <h4 className={`text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5 ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}>
                <UserPlus className={`w-3.5 h-3.5 ${isLight ? 'text-blue-600' : 'text-blue-400'}`} />
                Register New Identity into Database
              </h4>
              <span className={`text-[11px] ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                Saves login credentials and sets initial clearance
              </span>
            </div>

            {actionError && (
              <div className={`p-2 mb-3 rounded border text-xs flex items-center gap-2 ${
                isLight ? 'bg-rose-50 border-rose-200 text-rose-800' : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
              }`}>
                <ShieldAlert className={`w-3.5 h-3.5 shrink-0 ${isLight ? 'text-rose-600' : 'text-rose-400'}`} />
                <span>{actionError}</span>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
              <div>
                <label className={`block mb-1 font-medium ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>Username *</label>
                <input
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g. devops_elena"
                  className={`w-full px-2.5 py-1.5 border rounded-lg focus:outline-none focus:border-blue-500 font-mono ${
                    isLight ? 'bg-white border-slate-300 text-slate-900 placeholder-slate-400' : 'bg-slate-900 border-slate-700 text-white placeholder-slate-500'
                  }`}
                />
              </div>

              <div>
                <label className={`block mb-1 font-medium ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>Password (Min 8 chars) *</label>
                <input
                  type="password"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Create user password"
                  className={`w-full px-2.5 py-1.5 border rounded-lg focus:outline-none focus:border-blue-500 font-mono ${
                    isLight ? 'bg-white border-slate-300 text-slate-900 placeholder-slate-400' : 'bg-slate-900 border-slate-700 text-white placeholder-slate-500'
                  }`}
                />
              </div>

              <div>
                <label className={`block mb-1 font-medium ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>Role Clearance</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as any)}
                  className={`w-full px-2.5 py-1.5 border rounded-lg focus:outline-none focus:border-blue-500 ${
                    isLight ? 'bg-white border-slate-300 text-slate-900' : 'bg-slate-900 border-slate-700 text-white'
                  }`}
                >
                  <option value="Developer">Developer (Tier 1 &amp; 2)</option>
                  <option value="Admin">Admin (Full Control)</option>
                  <option value="Guest">Guest (Read Telemetry Only)</option>
                </select>
              </div>

              <div>
                <label className={`block mb-1 font-medium ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>Department / Team</label>
                <input
                  type="text"
                  value={newDept}
                  onChange={(e) => setNewDept(e.target.value)}
                  placeholder="e.g. Threat Intelligence"
                  className={`w-full px-2.5 py-1.5 border rounded-lg focus:outline-none focus:border-blue-500 ${
                    isLight ? 'bg-white border-slate-300 text-slate-900 placeholder-slate-400' : 'bg-slate-900 border-slate-700 text-white placeholder-slate-500'
                  }`}
                />
              </div>

              <div>
                <label className={`block mb-1 font-medium tabular-nums ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>
                  Base Threat Score ({newRisk}%)
                </label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  step="5"
                  value={newRisk}
                  onChange={(e) => setNewRisk(Number(e.target.value))}
                  className={`w-full accent-blue-600 h-2 rounded-lg cursor-pointer mt-1 ${isLight ? 'bg-slate-200' : 'bg-slate-800'}`}
                />
              </div>

              <div>
                <label className={`block mb-1 font-medium ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>Initial Approval Status</label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value as any)}
                  className={`w-full px-2.5 py-1.5 border rounded-lg focus:outline-none focus:border-blue-500 ${
                    isLight ? 'bg-white border-slate-300 text-slate-900' : 'bg-slate-900 border-slate-700 text-white'
                  }`}
                >
                  <option value="APPROVED">APPROVED (Immediate Clearance)</option>
                  <option value="PENDING_APPROVAL">PENDING_APPROVAL (Gated for Verification)</option>
                </select>
              </div>

              <div className="sm:col-span-2 md:col-span-3">
                <label className={`block mb-1 font-medium ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>
                  Access Justification / Note (Optional)
                </label>
                <input
                  type="text"
                  value={newJustification}
                  onChange={(e) => setNewJustification(e.target.value)}
                  placeholder="e.g. SRE contractor for edge pipeline deployments"
                  className={`w-full px-2.5 py-1.5 border rounded-lg focus:outline-none focus:border-blue-500 ${
                    isLight ? 'bg-white border-slate-300 text-slate-900 placeholder-slate-400' : 'bg-slate-900 border-slate-700 text-white placeholder-slate-500'
                  }`}
                />
              </div>
            </div>

            <div className={`flex justify-end gap-2 mt-3 pt-3 border-t ${isLight ? 'border-slate-200' : 'border-slate-800'}`}>
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className={`px-3 py-1.5 text-xs transition-colors cursor-pointer ${
                  isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-400 hover:text-white'
                }`}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-colors cursor-pointer"
              >
                {isSubmitting ? 'Saving to Database...' : 'Save Identity'}
              </button>
            </div>
          </form>
        )}

        {/* Users Table / Directory */}
        <div className="flex-1 overflow-y-auto p-4">
          {filteredUsers.length === 0 ? (
            <div className="text-center py-12 text-slate-500 text-xs">
              <Users className={`w-8 h-8 mx-auto mb-2 opacity-60 ${isLight ? 'text-slate-400' : 'text-slate-600'}`} />
              <p>No identities matched your filter query.</p>
              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setStatusFilter('ALL');
                  setRoleFilter('ALL');
                }}
                className="mt-2 text-blue-500 hover:underline text-xs cursor-pointer"
              >
                Reset Search Filters
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-2.5">
              {filteredUsers.map((user) => {
                const isPending = user.status === 'PENDING_APPROVAL';
                const isApproved = user.status === 'APPROVED';
                const isRejected = user.status === 'REJECTED';
                const isSuspended = user.status === 'SUSPENDED';
                const backupCount = Array.isArray(user.mfa_backup_codes) ? user.mfa_backup_codes.length : 0;

                return (
                  <div
                    key={user.id || user.username}
                    className={`p-3.5 rounded-xl border transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs ${
                      isLight
                        ? 'border-slate-200 bg-white hover:border-slate-300 shadow-xs'
                        : 'border-slate-800/80 bg-slate-950/50 hover:border-slate-700/80'
                    }`}
                  >
                    {/* User Identity Info */}
                    <div className="flex items-start gap-3 min-w-0">
                      <div
                        className={`w-9 h-9 rounded-xl flex items-center justify-center font-mono font-bold text-xs shrink-0 border ${
                          user.role === 'Admin'
                            ? isLight
                              ? 'bg-purple-50 border-purple-200 text-purple-700'
                              : 'bg-purple-950/40 border-purple-500/30 text-purple-300'
                            : user.role === 'Developer'
                            ? isLight
                              ? 'bg-blue-50 border-blue-200 text-blue-700'
                              : 'bg-blue-950/40 border-blue-500/30 text-blue-300'
                            : isLight
                            ? 'bg-slate-100 border-slate-200 text-slate-700'
                            : 'bg-slate-800 border-slate-700 text-slate-300'
                        }`}
                      >
                        {user.username.slice(0, 2).toUpperCase()}
                      </div>

                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`font-semibold font-mono text-sm ${isLight ? 'text-slate-900' : 'text-white'}`}>
                            {user.username}
                          </span>
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                              user.role === 'Admin'
                                ? isLight
                                  ? 'bg-purple-50 text-purple-700 border-purple-200'
                                  : 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                                : user.role === 'Developer'
                                ? isLight
                                  ? 'bg-blue-50 text-blue-700 border-blue-200'
                                  : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                                : isLight
                                ? 'bg-slate-100 text-slate-600 border-slate-200'
                                : 'bg-slate-800 text-slate-400 border-slate-700'
                            }`}
                          >
                            {user.role}
                          </span>

                          {/* Approval Status Badge */}
                          {isApproved && (
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${
                              isLight ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            }`}>
                              <CheckCircle2 className="w-2.5 h-2.5" />
                              Approved
                            </span>
                          )}
                          {isPending && (
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 font-semibold ${
                              isLight ? 'bg-amber-100 text-amber-800 border-amber-300' : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                            }`}>
                              <Clock className="w-2.5 h-2.5" />
                              Pending Verification
                            </span>
                          )}
                          {isRejected && (
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${
                              isLight ? 'bg-rose-50 text-rose-700 border-rose-200' : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                            }`}>
                              <XCircle className="w-2.5 h-2.5" />
                              Rejected
                            </span>
                          )}
                          {isSuspended && (
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${
                              isLight ? 'bg-purple-50 text-purple-700 border-purple-200' : 'bg-purple-500/15 text-purple-300 border-purple-500/30'
                            }`}>
                              <ShieldAlert className="w-2.5 h-2.5" />
                              Suspended
                            </span>
                          )}

                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${
                            user.mfa_enrolled
                              ? isLight
                                ? 'bg-blue-50 text-blue-700 border-blue-200'
                                : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                              : isLight
                              ? 'bg-amber-50 text-amber-800 border-amber-200'
                              : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                          }`}>
                            <Smartphone className={`w-2.5 h-2.5 ${user.mfa_enrolled ? (isLight ? 'text-blue-600' : 'text-blue-400') : (isLight ? 'text-amber-600' : 'text-amber-400')}`} />
                            {user.mfa_enrolled ? 'MFA Enrolled' : 'Pairing Pending (QR Next Login)'}
                          </span>

                          {backupCount > 0 && (
                            <span className={`text-[10px] font-mono tabular-nums px-2 py-0.5 rounded border flex items-center gap-1 ${
                              isLight ? 'bg-amber-50 text-amber-800 border-amber-200' : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                            }`}>
                              <LifeBuoy className={`w-2.5 h-2.5 ${isLight ? 'text-amber-600' : 'text-amber-400'}`} />
                              {backupCount} Recovery Codes
                            </span>
                          )}
                        </div>

                        <div className={`flex items-center gap-3 text-[11px] mt-1 flex-wrap ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                          {user.department && (
                            <span className="flex items-center gap-1">
                              <Building2 className="w-3 h-3 text-slate-500" />
                              {user.department}
                            </span>
                          )}
                          <div className="flex items-center gap-2 tabular-nums">
                            <span className="font-mono">
                              Risk:{' '}
                              <span
                                className={
                                  user.base_risk_score >= 75
                                    ? isLight ? 'text-rose-600 font-bold' : 'text-rose-400 font-bold'
                                    : user.base_risk_score >= 50
                                    ? isLight ? 'text-amber-600 font-bold' : 'text-amber-400 font-bold'
                                    : user.base_risk_score >= 25
                                    ? isLight ? 'text-cyan-600 font-bold' : 'text-cyan-400 font-bold'
                                    : isLight ? 'text-emerald-600 font-bold' : 'text-emerald-400 font-bold'
                                }
                              >
                                {user.base_risk_score}%
                              </span>
                            </span>

                            <div className={`w-16 h-1.5 rounded-full overflow-hidden border hidden sm:block ${
                              isLight ? 'bg-slate-200 border-slate-300' : 'bg-slate-900 border-slate-800'
                            }`}>
                              <div
                                className={`h-full transition-all ${
                                  user.base_risk_score >= 75
                                    ? 'bg-rose-500'
                                    : user.base_risk_score >= 50
                                    ? 'bg-amber-400'
                                    : user.base_risk_score >= 25
                                    ? 'bg-cyan-400'
                                    : 'bg-emerald-500'
                                }`}
                                style={{ width: `${Math.min(user.base_risk_score, 100)}%` }}
                              />
                            </div>

                            <span
                              className={`text-[9px] px-1.5 py-0.2 rounded font-mono font-bold uppercase tracking-wider border ${
                                user.base_risk_score >= 75
                                  ? isLight ? 'bg-rose-50 text-rose-700 border-rose-200' : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                                  : user.base_risk_score >= 50
                                  ? isLight ? 'bg-amber-50 text-amber-800 border-amber-200' : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                  : user.base_risk_score >= 25
                                  ? isLight ? 'bg-cyan-50 text-cyan-800 border-cyan-200' : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                                  : isLight ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                              }`}
                            >
                              {user.base_risk_score >= 75
                                ? 'HIGH THREAT'
                                : user.base_risk_score >= 50
                                ? 'ELEVATED'
                                : user.base_risk_score >= 25
                                ? 'MODERATE'
                                : 'NOMINAL'}
                            </span>
                          </div>
                        </div>

                        {user.requestJustification && (
                          <p className={`text-[11px] mt-1.5 italic px-2.5 py-1 rounded-md border ${
                            isLight ? 'text-slate-600 bg-slate-50 border-slate-200' : 'text-slate-400 bg-slate-900/60 border-slate-800'
                          }`}>
                            "{user.requestJustification}"
                          </p>
                        )}
                      </div>
                    </div>

                    {/* Action Controls */}
                    <div className="flex items-center gap-1.5 shrink-0 self-end sm:self-center flex-wrap">
                      {isPending && (
                        <>
                          <button
                            type="button"
                            disabled={processingApprovalUser === user.username}
                            onClick={() => handleApprovePendingUser(user.username)}
                            className={`px-2.5 py-1 text-xs font-semibold rounded-lg disabled:opacity-50 border flex items-center gap-1 transition-colors cursor-pointer ${
                              isLight
                                ? 'bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border-emerald-300'
                                : 'bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border-emerald-500/30'
                            }`}
                            title="Verify and Approve user for login"
                          >
                            <CheckCircle2 className={`w-3.5 h-3.5 ${isLight ? 'text-emerald-600' : 'text-emerald-400'}`} />
                            <span>{processingApprovalUser === user.username ? 'Approving...' : 'Approve'}</span>
                          </button>
                          <button
                            type="button"
                            disabled={processingApprovalUser === user.username}
                            onClick={() => handleRejectPendingUser(user.username)}
                            className={`px-2.5 py-1 text-xs font-semibold rounded-lg disabled:opacity-50 border flex items-center gap-1 transition-colors cursor-pointer ${
                              isLight
                                ? 'bg-rose-50 hover:bg-rose-100 text-rose-700 border-rose-300'
                                : 'bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border-rose-500/30'
                            }`}
                            title="Reject user request"
                          >
                            <XCircle className={`w-3.5 h-3.5 ${isLight ? 'text-rose-600' : 'text-rose-400'}`} />
                            <span>{processingApprovalUser === user.username ? 'Rejecting...' : 'Reject'}</span>
                          </button>
                        </>
                      )}

                      {/* FEATURE 1: Security Credentials Inspector (Admin in Dev Mode) */}
                      {isDevMode && (
                        <button
                          type="button"
                          onClick={() => handleOpenSecurityCredentials(user)}
                          disabled={isLoadingCredentials === user.username}
                          className={`px-2.5 py-1 text-xs font-semibold rounded-lg border flex items-center gap-1.5 transition-all shadow-xs cursor-pointer ${
                            isLight
                              ? 'bg-blue-50 hover:bg-blue-100 text-blue-700 border-blue-200 hover:border-blue-400'
                              : 'bg-blue-950/40 hover:bg-blue-900/60 text-blue-300 border-blue-800/60 hover:border-blue-500'
                          }`}
                          title="Inspect Base32 TOTP secret, live token, and OTP auth URI for troubleshooting MFA mismatches"
                        >
                          <KeyRound className={`w-3.5 h-3.5 ${isLight ? 'text-blue-600' : 'text-blue-400'}`} />
                          <span>
                            {isLoadingCredentials === user.username ? 'Loading...' : 'Security Credentials'}
                          </span>
                        </button>
                      )}

                      {/* FEATURE 2: Generate Single-Use Recovery Codes */}
                      <button
                        type="button"
                        onClick={() => handleGenerateRecoveryCodes(user.username)}
                        disabled={isGeneratingRecovery === user.username}
                        className={`px-2.5 py-1 text-xs font-semibold rounded-lg border flex items-center gap-1.5 transition-all shadow-xs cursor-pointer ${
                          isLight
                            ? 'bg-amber-50 hover:bg-amber-100 text-amber-800 border-amber-200 hover:border-amber-400'
                            : 'bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 border-amber-800/60 hover:border-amber-500'
                        }`}
                        title="Generate 8 single-use high-entropy recovery bypass codes and store in user profile"
                      >
                        <LifeBuoy className={`w-3.5 h-3.5 ${isLight ? 'text-amber-600' : 'text-amber-400'}`} />
                        <span>
                          {isGeneratingRecovery === user.username ? 'Generating...' : 'Recovery Codes'}
                        </span>
                      </button>

                      {/* FEATURE 3: Reset MFA Pairing (re-enables first-time QR setup on next sign-in) */}
                      <button
                        type="button"
                        onClick={() => handleResetMfaEnrollment(user.username)}
                        disabled={resettingMfaUser === user.username}
                        className={`px-2.5 py-1 text-xs font-semibold rounded-lg border flex items-center gap-1.5 transition-all shadow-xs cursor-pointer ${
                          isLight
                            ? 'bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border-indigo-200 hover:border-indigo-400'
                            : 'bg-indigo-950/40 hover:bg-indigo-900/60 text-indigo-300 border-indigo-800/60 hover:border-indigo-500'
                        }`}
                        title="Rotate MFA key and enable one-time QR pairing on next login"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${isLight ? 'text-indigo-600' : 'text-indigo-400'} ${resettingMfaUser === user.username ? 'animate-spin' : ''}`} />
                        <span>
                          {resettingMfaUser === user.username ? 'Resetting...' : 'Reset MFA'}
                        </span>
                      </button>

                      {/* Real-time Session Revocation Action */}
                      {onRevokeSession && (
                        <button
                          type="button"
                          id={`btn-revoke-session-${user.username}`}
                          disabled={revokingUser === user.username}
                          onClick={() => {
                            setConfirmRevokeUser(user);
                          }}
                          className={`px-2.5 py-1 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-all shadow-xs cursor-pointer ${
                            revokedUsersList.has(user.username)
                              ? isLight
                                ? 'bg-rose-100 text-rose-800 border border-rose-300'
                                : 'bg-rose-500/30 text-rose-300 border border-rose-500/60'
                              : isLight
                              ? 'bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 hover:border-rose-400'
                              : 'bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/60 hover:border-rose-500'
                          }`}
                          title={`Terminate ${user.username}'s active session record in the database.`}
                        >
                          <ShieldAlert className={`w-3.5 h-3.5 ${isLight ? 'text-rose-600' : 'text-rose-400'}`} />
                          <span>
                            {revokingUser === user.username
                              ? 'Revoking...'
                              : revokedUsersList.has(user.username)
                              ? 'Session Terminated'
                              : 'Revoke Session'}
                          </span>
                        </button>
                      )}

                      {user.username !== 'secops_admin' && (
                        <button
                          type="button"
                          onClick={() => onDeleteUser(user.username)}
                          className={`p-1.5 rounded-lg transition-colors cursor-pointer ${
                            isLight ? 'text-slate-500 hover:text-rose-600 hover:bg-rose-50' : 'text-slate-500 hover:text-rose-400 hover:bg-rose-950/40'
                          }`}
                          title="Delete from database"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </>
    )}

    {/* Dedicated Pending Requests Tab Panel */}
    {modalTab === 'pending_users' && (
      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {/* Banner with Zero-Trust Policy Notice */}
        <div
          className={`p-4 rounded-xl border text-xs space-y-2 ${
            isLight
              ? 'bg-amber-50 border-amber-200 text-amber-900'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-200/90'
          }`}
        >
          <div className={`flex items-center gap-2 font-bold ${isLight ? 'text-amber-800' : 'text-amber-300'}`}>
            <ShieldCheck className={`w-4 h-4 ${isLight ? 'text-amber-600' : 'text-amber-400'}`} />
            <span>Zero-Trust Pending Identity Clearances &amp; Verification Gate</span>
          </div>
          <p className={`text-[11px] leading-relaxed ${isLight ? 'text-amber-900/90' : 'text-slate-300'}`}>
            Principals who self-register are held in <strong>PENDING_APPROVAL</strong> status until authorized by a SecOps Administrator. Clicking <strong>"Approve"</strong> transitions the user record to <code>APPROVED</code>, enables RFC 6238 MFA token issuance, and records an administrative decision in the tamper-evident audit ledger. Clicking <strong>"Reject"</strong> denies access fail-closed.
          </p>
        </div>

        {/* Section Header */}
        <div
          className={`flex items-center justify-between text-xs px-1 border-b pb-2.5 ${
            isLight ? 'text-slate-600 border-slate-200' : 'text-slate-400 border-slate-800'
          }`}
        >
          <div className="flex items-center gap-2">
            <Clock className={`w-4 h-4 ${isLight ? 'text-amber-600' : 'text-amber-400'}`} />
            <span className={`font-bold text-sm tabular-nums ${isLight ? 'text-slate-900' : 'text-white'}`}>
              Pending Clearance Requests ({pendingUsers.length})
            </span>
          </div>
          <span className={`text-[11px] font-mono tabular-nums ${isLight ? 'text-amber-700' : 'text-amber-400'}`}>
            {pendingUsers.length === 1 ? '1 User Awaiting Review' : `${pendingUsers.length} Users Awaiting Review`}
          </span>
        </div>

        {/* Pending Users List */}
        {pendingUsers.length === 0 ? (
          <div className="text-center py-16 text-slate-500 text-xs space-y-3">
            <div
              className={`w-12 h-12 rounded-full border flex items-center justify-center mx-auto ${
                isLight
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-600'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              }`}
            >
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <p className={`font-semibold text-sm ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>No Pending Requests</p>
            <p className="text-[11px] text-slate-500 max-w-md mx-auto">
              All user registrations and access requests have been cleared. New accounts submitted through the Zero-Trust Gateway will appear here for verification.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3">
            {pendingUsers.map((user) => (
              <div
                key={user.id || user.username}
                className={`p-4 rounded-xl border transition-all space-y-3 text-xs ${
                  isLight
                    ? 'border-amber-200 bg-white hover:border-amber-300 shadow-sm'
                    : 'border-amber-500/30 bg-slate-950/90 hover:border-amber-500/50 shadow-lg shadow-black/40'
                }`}
              >
                <div
                  className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b pb-3 ${
                    isLight ? 'border-slate-200' : 'border-slate-800/80'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div
                      className={`w-10 h-10 rounded-xl border flex items-center justify-center font-mono font-bold text-sm shrink-0 ${
                        isLight
                          ? 'bg-amber-50 border-amber-200 text-amber-700'
                          : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                      }`}
                    >
                      {user.username.slice(0, 2).toUpperCase()}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`font-bold font-mono text-sm ${isLight ? 'text-slate-900' : 'text-white'}`}>
                          {user.username}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                            isLight
                              ? 'bg-blue-50 text-blue-700 border-blue-200'
                              : 'bg-blue-500/15 text-blue-300 border-blue-500/30'
                          }`}
                        >
                          Role: {user.role}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold flex items-center gap-1 ${
                            isLight
                              ? 'bg-amber-50 text-amber-700 border-amber-300'
                              : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          }`}
                        >
                          <Clock className="w-2.5 h-2.5" />
                          PENDING_APPROVAL
                        </span>
                      </div>
                      <div className={`text-[11px] mt-0.5 flex items-center gap-2 flex-wrap ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                        {user.department && (
                          <span className="flex items-center gap-1">
                            <Building2 className="w-3 h-3 text-slate-500" />
                            {user.department}
                          </span>
                        )}
                        <span aria-hidden="true">·</span>
                        <span className="font-mono text-slate-500 tabular-nums">
                          Registered: {user.created_at || user.createdAt ? new Date(user.created_at || user.createdAt).toISOString() : 'Recent registration'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Approve / Reject Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      disabled={processingApprovalUser === user.username}
                      onClick={() => handleApprovePendingUser(user.username)}
                      className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold text-xs flex items-center gap-1.5 transition-all shadow-sm cursor-pointer"
                      title={`Approve ${user.username} and activate access in database`}
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{processingApprovalUser === user.username ? 'Approving...' : 'Approve Access'}</span>
                    </button>
                    <button
                      type="button"
                      disabled={processingApprovalUser === user.username}
                      onClick={() => handleRejectPendingUser(user.username)}
                      className={`px-3 py-1.5 rounded-lg disabled:opacity-50 border text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
                        isLight
                          ? 'bg-slate-100 hover:bg-rose-50 text-slate-700 hover:text-rose-700 border-slate-300 hover:border-rose-300'
                          : 'bg-slate-800 hover:bg-rose-950/50 text-slate-300 hover:text-rose-300 border-slate-700 hover:border-rose-700/50'
                      }`}
                      title={`Reject ${user.username}'s clearance request`}
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>{processingApprovalUser === user.username ? 'Rejecting...' : 'Reject'}</span>
                    </button>
                  </div>
                </div>

                {/* Justification & Risk Info */}
                <div
                  className={`grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] p-2.5 rounded-lg border ${
                    isLight
                      ? 'text-slate-600 bg-slate-50 border-slate-200'
                      : 'text-slate-400 bg-slate-900/60 border-slate-800/60'
                  }`}
                >
                  <div>
                    <span className="text-slate-500 font-medium">Access Justification: </span>
                    <span className={`italic ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
                      {user.requestJustification || 'Self-service identity clearance request'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between sm:justify-end gap-2">
                    <span className="text-slate-500 font-medium">Base Risk Assessment: </span>
                    <span className={`font-mono font-bold tabular-nums ${isLight ? 'text-amber-700' : 'text-amber-400'}`}>
                      {user.base_risk_score}%
                    </span>
                    <div
                      className={`w-16 h-1.5 rounded-full overflow-hidden border ${
                        isLight ? 'bg-slate-200 border-slate-300' : 'bg-slate-900 border-slate-800'
                      }`}
                    >
                      <div
                        className="h-full bg-amber-500"
                        style={{ width: `${Math.min(user.base_risk_score, 100)}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    )}

    {/* Credential & Identity Change Requests Tab Panel */}
    {modalTab === 'password_requests' && (
      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        <div
          className={`p-4 rounded-xl border text-xs space-y-2 ${
            isLight
              ? 'bg-amber-50 border-amber-200 text-amber-900'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-200/90'
          }`}
        >
          <div className={`flex items-center gap-2 font-bold ${isLight ? 'text-amber-800' : 'text-amber-300'}`}>
            <ShieldCheck className={`w-4 h-4 ${isLight ? 'text-amber-600' : 'text-amber-400'}`} />
            <span>Zero-Trust Credential &amp; Identity Governance Policy</span>
          </div>
          <p className={`text-[11px] leading-relaxed ${isLight ? 'text-amber-900/90' : 'text-slate-300'}`}>
            To guarantee fail-closed security, all password and username change requests submitted by users are held in a pending state until explicitly accepted by an Administrator. Upon clicking <strong>"Accept &amp; Save to DB"</strong>, changes are atomically committed into the Cloudflare D1 / SQLite database (passwords stored as salted PBKDF2 hashes; usernames checked for uniqueness and updated), and any active sessions are revoked. Plaintext passwords are never displayed or stored.
          </p>
        </div>

        {/* Sub-Filters: All, Password, Username */}
        <div
          className={`flex items-center justify-between gap-3 flex-wrap border-b pb-3 ${
            isLight ? 'border-slate-200' : 'border-slate-800'
          }`}
        >
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setChangeRequestFilter('ALL')}
              className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer tabular-nums ${
                changeRequestFilter === 'ALL'
                  ? 'bg-blue-600 text-white'
                  : isLight
                  ? 'bg-white text-slate-600 border border-slate-200 hover:text-slate-900'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'
              }`}
            >
              All Requests ({passwordRequests.length + usernameRequests.length})
            </button>
            <button
              type="button"
              onClick={() => setChangeRequestFilter('PASSWORD')}
              className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 tabular-nums ${
                changeRequestFilter === 'PASSWORD'
                  ? 'bg-amber-600 text-white'
                  : isLight
                  ? 'bg-white text-slate-600 border border-slate-200 hover:text-slate-900'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'
              }`}
            >
              <KeyRound className="w-3 h-3" />
              <span>Password ({passwordRequests.length})</span>
              {pendingPasswordRequestsCount > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-400 text-slate-950 font-mono tabular-nums">
                  {pendingPasswordRequestsCount}
                </span>
              )}
            </button>
            <button
              type="button"
              onClick={() => setChangeRequestFilter('USERNAME')}
              className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 tabular-nums ${
                changeRequestFilter === 'USERNAME'
                  ? 'bg-purple-600 text-white'
                  : isLight
                  ? 'bg-white text-slate-600 border border-slate-200 hover:text-slate-900'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'
              }`}
            >
              <Users className="w-3 h-3" />
              <span>Username ({usernameRequests.length})</span>
              {pendingUsernameRequestsCount > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-purple-400 text-slate-950 font-mono tabular-nums">
                  {pendingUsernameRequestsCount}
                </span>
              )}
            </button>
          </div>

          <span className={`text-[11px] font-mono tabular-nums ${isLight ? 'text-amber-700' : 'text-amber-400'}`}>
            {totalPendingChangeRequests} Total Pending Acceptance
          </span>
        </div>

        {/* Requests List */}
        {((changeRequestFilter === 'ALL' && passwordRequests.length === 0 && usernameRequests.length === 0) ||
          (changeRequestFilter === 'PASSWORD' && passwordRequests.length === 0) ||
          (changeRequestFilter === 'USERNAME' && usernameRequests.length === 0)) ? (
          <div className="text-center py-16 text-slate-500 text-xs space-y-2">
            <KeyRound className="w-10 h-10 mx-auto text-slate-500 opacity-60" />
            <p className={`font-medium ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>No change requests matching the selected filter.</p>
            <p className="text-[11px] text-slate-500">
              Users can submit password and username change requests from the Login Gateway or profile interface.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {/* 1. PASSWORD REQUESTS */}
            {(changeRequestFilter === 'ALL' || changeRequestFilter === 'PASSWORD') && passwordRequests.length > 0 && (
              <div className="space-y-2.5">
                <div className={`text-xs font-bold flex items-center gap-1.5 px-1 tabular-nums ${isLight ? 'text-amber-700' : 'text-amber-300'}`}>
                  <KeyRound className="w-3.5 h-3.5" />
                  <span>Password Change Requests ({passwordRequests.length})</span>
                </div>
                <div className="grid grid-cols-1 gap-2.5">
                  {passwordRequests.map((req) => (
                    <div
                      key={req.id}
                      className={`p-4 rounded-xl border transition-all space-y-3 text-xs ${
                        isLight
                          ? 'border-slate-200 bg-white hover:border-slate-300 shadow-sm'
                          : 'border-slate-800 bg-slate-950/80 hover:border-slate-700'
                      }`}
                    >
                      <div
                        className={`flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-2.5 ${
                          isLight ? 'border-slate-200' : 'border-slate-800/80'
                        }`}
                      >
                        <div className="flex items-center gap-2.5">
                          <div
                            className={`w-8 h-8 rounded-lg border flex items-center justify-center font-mono font-bold ${
                              isLight
                                ? 'bg-amber-50 border-amber-200 text-amber-700'
                                : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                            }`}
                          >
                            <KeyRound className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className={`font-mono text-sm font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>
                                {req.username}
                              </span>
                              <span
                                className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                                  req.status === 'PENDING'
                                    ? isLight
                                      ? 'bg-amber-50 text-amber-700 border-amber-200'
                                      : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                    : req.status === 'APPROVED'
                                    ? isLight
                                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                      : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                    : isLight
                                    ? 'bg-rose-50 text-rose-700 border-rose-200'
                                    : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                                }`}
                              >
                                {req.status === 'PENDING' ? 'Awaiting Admin Acceptance' : req.status}
                              </span>
                            </div>
                            <span className="text-[11px] text-slate-500 font-mono tabular-nums">
                              Request ID: {req.id} · Requested {new Date(req.requested_at).toLocaleString()}
                            </span>
                          </div>
                        </div>

                        {req.status === 'PENDING' && (
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              disabled={processingRequestId === req.id}
                              onClick={() => handleApprovePasswordRequest(req.id)}
                              className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer disabled:opacity-50"
                            >
                              <Check className="w-3.5 h-3.5" />
                              <span>{processingRequestId === req.id ? 'Saving to DB...' : 'Accept & Save to DB'}</span>
                            </button>
                            <button
                              type="button"
                              disabled={processingRequestId === req.id}
                              onClick={() => handleRejectPasswordRequest(req.id)}
                              className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 ${
                                isLight
                                  ? 'bg-slate-100 hover:bg-rose-50 text-slate-700 hover:text-rose-700 border-slate-300 hover:border-rose-300'
                                  : 'bg-slate-800 hover:bg-rose-950/40 text-slate-300 hover:text-rose-300 border-slate-700 hover:border-rose-700/50'
                              }`}
                            >
                              <X className="w-3.5 h-3.5" />
                              <span>Reject</span>
                            </button>
                          </div>
                        )}

                        {req.status === 'APPROVED' && (
                          <div className={`flex items-center gap-1.5 font-mono text-[11px] ${isLight ? 'text-emerald-700' : 'text-emerald-400'}`}>
                            <CheckCircle2 className="w-4 h-4" />
                            <span>Saved in Database by {req.reviewed_by || 'secops_admin'}</span>
                          </div>
                        )}

                        {req.status === 'REJECTED' && (
                          <div className={`flex items-center gap-1.5 font-mono text-[11px] ${isLight ? 'text-rose-700' : 'text-rose-400'}`}>
                            <XCircle className="w-4 h-4" />
                            <span>Rejected by {req.reviewed_by || 'secops_admin'}</span>
                          </div>
                        )}
                      </div>

                      <div
                        className={`grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] p-2.5 rounded-lg border ${
                          isLight
                            ? 'text-slate-600 bg-slate-50 border-slate-200'
                            : 'text-slate-400 bg-slate-900/50 border-slate-800/60'
                        }`}
                      >
                        <div>
                          <span className="text-slate-500 font-medium">Justification: </span>
                          <span className={isLight ? 'text-slate-700' : 'text-slate-300'}>{req.justification || 'Standard rotation'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 font-medium">Cryptographic Storage: </span>
                          <span className={`font-mono ${isLight ? 'text-emerald-700' : 'text-emerald-400'}`}>PBKDF2 SHA-512 (Secret masked: ••••••••)</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 2. USERNAME REQUESTS */}
            {(changeRequestFilter === 'ALL' || changeRequestFilter === 'USERNAME') && usernameRequests.length > 0 && (
              <div className="space-y-2.5">
                <div className={`text-xs font-bold flex items-center gap-1.5 px-1 tabular-nums ${isLight ? 'text-purple-700' : 'text-purple-300'}`}>
                  <Users className="w-3.5 h-3.5" />
                  <span>Username Change Requests ({usernameRequests.length})</span>
                </div>
                <div className="grid grid-cols-1 gap-2.5">
                  {usernameRequests.map((req) => (
                    <div
                      key={req.id}
                      className={`p-4 rounded-xl border transition-all space-y-3 text-xs ${
                        isLight
                          ? 'border-slate-200 bg-white hover:border-slate-300 shadow-sm'
                          : 'border-slate-800 bg-slate-950/80 hover:border-slate-700'
                      }`}
                    >
                      <div
                        className={`flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-2.5 ${
                          isLight ? 'border-slate-200' : 'border-slate-800/80'
                        }`}
                      >
                        <div className="flex items-center gap-2.5">
                          <div
                            className={`w-8 h-8 rounded-lg border flex items-center justify-center font-mono font-bold ${
                              isLight
                                ? 'bg-purple-50 border-purple-200 text-purple-700'
                                : 'bg-purple-500/10 border-purple-500/30 text-purple-400'
                            }`}
                          >
                            <UserCheck className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className={`font-mono text-sm font-bold line-through ${isLight ? 'text-slate-500' : 'text-slate-300'}`}>
                                {req.current_username}
                              </span>
                              <span className="text-slate-400 text-xs">→</span>
                              <span className={`font-mono text-sm font-bold ${isLight ? 'text-purple-700' : 'text-purple-300'}`}>
                                {req.requested_username}
                              </span>
                              <span
                                className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                                  req.status === 'PENDING'
                                    ? isLight
                                      ? 'bg-amber-50 text-amber-700 border-amber-200'
                                      : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                    : req.status === 'APPROVED'
                                    ? isLight
                                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                      : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                    : isLight
                                    ? 'bg-rose-50 text-rose-700 border-rose-200'
                                    : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                                }`}
                              >
                                {req.status === 'PENDING' ? 'Awaiting Admin Acceptance' : req.status}
                              </span>
                            </div>
                            <span className="text-[11px] text-slate-500 font-mono tabular-nums">
                              Request ID: {req.id} · Requested {new Date(req.requested_at).toLocaleString()}
                            </span>
                          </div>
                        </div>

                        {req.status === 'PENDING' && (
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              disabled={processingRequestId === req.id}
                              onClick={() => handleApproveUsernameRequest(req.id)}
                              className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer disabled:opacity-50"
                            >
                              <Check className="w-3.5 h-3.5" />
                              <span>{processingRequestId === req.id ? 'Updating DB...' : 'Accept & Save to DB'}</span>
                            </button>
                            <button
                              type="button"
                              disabled={processingRequestId === req.id}
                              onClick={() => handleRejectUsernameRequest(req.id)}
                              className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 ${
                                isLight
                                  ? 'bg-slate-100 hover:bg-rose-50 text-slate-700 hover:text-rose-700 border-slate-300 hover:border-rose-300'
                                  : 'bg-slate-800 hover:bg-rose-950/40 text-slate-300 hover:text-rose-300 border-slate-700 hover:border-rose-700/50'
                              }`}
                            >
                              <X className="w-3.5 h-3.5" />
                              <span>Reject</span>
                            </button>
                          </div>
                        )}

                        {req.status === 'APPROVED' && (
                          <div className={`flex items-center gap-1.5 font-mono text-[11px] ${isLight ? 'text-emerald-700' : 'text-emerald-400'}`}>
                            <CheckCircle2 className="w-4 h-4" />
                            <span>Updated in Database by {req.reviewed_by || 'secops_admin'}</span>
                          </div>
                        )}

                        {req.status === 'REJECTED' && (
                          <div className={`flex items-center gap-1.5 font-mono text-[11px] ${isLight ? 'text-rose-700' : 'text-rose-400'}`}>
                            <XCircle className="w-4 h-4" />
                            <span>Rejected by {req.reviewed_by || 'secops_admin'}</span>
                          </div>
                        )}
                      </div>

                      <div
                        className={`grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] p-2.5 rounded-lg border ${
                          isLight
                            ? 'text-slate-600 bg-slate-50 border-slate-200'
                            : 'text-slate-400 bg-slate-900/50 border-slate-800/60'
                        }`}
                      >
                        <div>
                          <span className="text-slate-500 font-medium">Justification: </span>
                          <span className={isLight ? 'text-slate-700' : 'text-slate-300'}>{req.justification || 'Self-service identity update'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 font-medium">Database Action on Approval: </span>
                          <span className={`font-mono ${isLight ? 'text-purple-700' : 'text-purple-400'}`}>Updates users.username &amp; invalidates old sessions</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    )}

        {/* Modal Footer */}
        <div
          className={`p-3.5 border-t flex items-center justify-between text-xs ${
            isLight
              ? 'border-slate-200 bg-slate-50 text-slate-600'
              : 'border-slate-800 bg-slate-950/60 text-slate-400'
          }`}
        >
          <span className="font-mono text-[11px]">
            Cloudflare D1 SQLite &amp; Edge IAM Engine · RFC 6238 MFA Protected
          </span>
          <button
            type="button"
            onClick={onClose}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer font-medium ${
              isLight
                ? 'bg-slate-200 hover:bg-slate-300 text-slate-800'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
            }`}
          >
            Close Directory
          </button>
        </div>
      </div>

      {/* MODAL 1: SECURITY CREDENTIALS INSPECTOR (Enrollment & Window Metadata Only) */}
      {securityCredentialsUser && (
        <div className="fixed inset-0 z-60 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div
            className={`border rounded-2xl p-6 max-w-lg w-full shadow-2xl relative animate-in fade-in zoom-in-95 duration-150 space-y-4 ${
              isLight ? 'bg-white border-blue-200' : 'bg-slate-900 border-blue-500/50'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div
                  className={`w-10 h-10 rounded-xl border flex items-center justify-center shrink-0 ${
                    isLight
                      ? 'bg-blue-50 border-blue-200 text-blue-600'
                      : 'bg-blue-500/20 border-blue-500/40 text-blue-400'
                  }`}
                >
                  <KeyRound className="w-5 h-5" />
                </div>
                <div>
                  <h3 className={`text-base font-bold flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                    <span>Security Credentials Status</span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        isLight
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      }`}
                    >
                      Protected
                    </span>
                  </h3>
                  <p className={`text-xs ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                    Inspect RFC 6238 enrollment posture and 30s time window alignment for{' '}
                    <span className={`font-mono font-semibold ${isLight ? 'text-slate-900' : 'text-white'}`}>
                      [{securityCredentialsUser.username}]
                    </span>.
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setSecurityCredentialsUser(null)}
                className={`p-1 rounded-lg transition-colors cursor-pointer ${
                  isLight ? 'text-slate-500 hover:text-slate-900' : 'text-slate-400 hover:text-white'
                }`}
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Synchronized 30s Window Telemetry */}
            <div
              className={`p-4 rounded-xl border space-y-2.5 ${
                isLight ? 'bg-slate-50 border-blue-200' : 'bg-slate-950 border-blue-500/30'
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className={`flex items-center gap-1.5 tabular-nums ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                  <Clock className={`w-3.5 h-3.5 ${isLight ? 'text-blue-600' : 'text-blue-400'}`} />
                  TOTP 30-Second Time-Step Window #{securityCredentialsUser.timeStep30s}
                </span>
                <span className={`text-[11px] font-mono font-bold tabular-nums ${isLight ? 'text-blue-700' : 'text-blue-400'}`}>
                  {securityCredentialsUser.secondsRemaining}s remaining
                </span>
              </div>

              <div className={`w-full h-1.5 rounded-full overflow-hidden ${isLight ? 'bg-slate-200' : 'bg-slate-800'}`}>
                <div
                  className="bg-blue-500 h-full transition-all duration-1000 ease-linear rounded-full"
                  style={{ width: `${(securityCredentialsUser.secondsRemaining / 30) * 100}%` }}
                />
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1 text-xs">
                <div
                  className={`p-2.5 rounded-lg border ${
                    isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'
                  }`}
                >
                  <span className={`block text-[10px] ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>MFA Enforcement</span>
                  <span
                    className={
                      securityCredentialsUser.mfa_enabled
                        ? isLight
                          ? 'text-emerald-700 font-bold'
                          : 'text-emerald-400 font-bold'
                        : isLight
                        ? 'text-amber-700 font-bold'
                        : 'text-amber-400 font-bold'
                    }
                  >
                    {securityCredentialsUser.mfa_enabled ? 'ENABLED (RFC 6238)' : 'DISABLED'}
                  </span>
                </div>
                <div
                  className={`p-2.5 rounded-lg border ${
                    isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'
                  }`}
                >
                  <span className={`block text-[10px] ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>Secret Enrollment</span>
                  <span
                    className={
                      securityCredentialsUser.mfaConfigured
                        ? isLight
                          ? 'text-emerald-700 font-bold'
                          : 'text-emerald-400 font-bold'
                        : isLight
                        ? 'text-rose-700 font-bold'
                        : 'text-rose-400 font-bold'
                    }
                  >
                    {securityCredentialsUser.mfaConfigured ? 'CONFIGURED (SEALED)' : 'NOT ENROLLED'}
                  </span>
                </div>
              </div>
            </div>

            {/* Enrollment Issuer & Server Time Metadata */}
            <div
              className={`p-3.5 rounded-xl border space-y-2 text-xs ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/80 border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Authenticator Issuer:</span>
                <span className={`font-mono ${isLight ? 'text-slate-900' : 'text-slate-200'}`}>{securityCredentialsUser.issuer}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Assigned Principal Role:</span>
                <span className={`font-mono ${isLight ? 'text-blue-700' : 'text-blue-300'}`}>{securityCredentialsUser.role}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Server Sync Timestamp:</span>
                <span className={`font-mono tabular-nums ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>{securityCredentialsUser.serverTimeIso}</span>
              </div>
              <p className={`text-[11px] pt-1 border-t ${isLight ? 'text-slate-600 border-slate-200' : 'text-slate-500 border-slate-800'}`}>
                For Zero-Trust compliance, shared Base32 TOTP keys and live OTPs remain sealed on the server and are never exposed via API responses. Use Regenerate Recovery Codes if an authenticator device is lost.
              </p>
            </div>

            <div className={`flex items-center justify-between text-xs pt-1 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              <span>
                Single-use bypass codes stored:{' '}
                <strong className={`font-mono tabular-nums ${isLight ? 'text-amber-700' : 'text-amber-400'}`}>
                  {securityCredentialsUser.backupCodesCount}
                </strong>
              </span>
              <button
                type="button"
                onClick={() => setSecurityCredentialsUser(null)}
                className={`px-4 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${
                  isLight
                    ? 'bg-slate-200 hover:bg-slate-300 text-slate-800'
                    : 'bg-slate-800 hover:bg-slate-700 text-white'
                }`}
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: GENERATED RECOVERY CODES MODAL */}
      {recoveryCodesModal && (
        <div className="fixed inset-0 z-60 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div
            className={`border rounded-2xl p-6 max-w-lg w-full shadow-2xl relative animate-in fade-in zoom-in-95 duration-150 space-y-4 ${
              isLight ? 'bg-white border-amber-300' : 'bg-slate-900 border-amber-500/50'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div
                  className={`w-10 h-10 rounded-xl border flex items-center justify-center shrink-0 ${
                    isLight
                      ? 'bg-amber-50 border-amber-200 text-amber-600'
                      : 'bg-amber-500/20 border-amber-500/40 text-amber-400'
                  }`}
                >
                  <LifeBuoy className="w-5 h-5" />
                </div>
                <div>
                  <h3 className={`text-base font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>
                    Single-Use Recovery Bypass Codes
                  </h3>
                  <p className={`text-xs ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                    Generated 8 emergency bypass codes for{' '}
                    <span className={`font-mono font-semibold ${isLight ? 'text-slate-900' : 'text-white'}`}>
                      [{recoveryCodesModal.username}]
                    </span>.
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setRecoveryCodesModal(null)}
                className={`p-1 rounded-lg transition-colors cursor-pointer ${
                  isLight ? 'text-slate-500 hover:text-slate-900' : 'text-slate-400 hover:text-white'
                }`}
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div
              className={`p-3 rounded-xl border text-xs leading-relaxed ${
                isLight
                  ? 'bg-amber-50 border-amber-200 text-amber-900'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-200'
              }`}
            >
              <strong className={`block font-bold mb-0.5 ${isLight ? 'text-amber-800' : 'text-amber-300'}`}>
                Important Security Notice:
              </strong>
              Each code can only be used once to bypass MFA if the physical TOTP authenticator device is lost. Once consumed, the code is permanently invalidated. Store these codes in an encrypted password vault.
            </div>

            {/* 8 Codes Grid */}
            <div
              className={`grid grid-cols-2 gap-2 p-3 rounded-xl border font-mono text-sm tabular-nums ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
              }`}
            >
              {recoveryCodesModal.codes.map((code, idx) => (
                <div
                  key={idx}
                  className={`p-2 rounded border flex items-center justify-between font-bold tracking-wider ${
                    isLight
                      ? 'bg-white border-slate-200 text-slate-900'
                      : 'bg-slate-900 border-slate-800 text-white'
                  }`}
                >
                  <span className="text-slate-500 text-xs font-normal tabular-nums">#{idx + 1}</span>
                  <span className={`tabular-nums ${isLight ? 'text-amber-700' : 'text-amber-300'}`}>{code}</span>
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => {
                  const content = `Serverless Zero-Trust Recovery Codes\nUser: ${recoveryCodesModal.username}\nGenerated: ${new Date().toISOString()}\n\n${recoveryCodesModal.codes.map((c, i) => `${i + 1}. ${c}`).join('\n')}\n\nNote: Each code is single-use.`;
                  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `recovery_codes_${recoveryCodesModal.username}_${new Date().toISOString().slice(0, 10)}.txt`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
                className={`px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5 border cursor-pointer transition-colors ${
                  isLight
                    ? 'bg-slate-100 hover:bg-slate-200 text-slate-800 border-slate-300'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                }`}
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .txt</span>
              </button>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    const str = recoveryCodesModal.codes.join('\n');
                    navigator.clipboard.writeText(str);
                    setCopiedCodes(true);
                    setTimeout(() => setCopiedCodes(false), 2000);
                  }}
                  className={`px-3.5 py-2 rounded-xl border text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-colors ${
                    isLight
                      ? 'bg-blue-50 hover:bg-blue-100 text-blue-700 border-blue-200'
                      : 'bg-blue-600/30 hover:bg-blue-600/40 text-blue-300 border-blue-500/40'
                  }`}
                >
                  {copiedCodes ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedCodes ? 'Copied All' : 'Copy All Codes'}</span>
                </button>

                <button
                  type="button"
                  onClick={() => setRecoveryCodesModal(null)}
                  className="px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold cursor-pointer"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CONFIRM REVOCATION MODAL */}
      {confirmRevokeUser && (
        <div className="fixed inset-0 z-60 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div
            className={`border rounded-2xl p-5 max-w-md w-full shadow-2xl relative animate-in fade-in zoom-in-95 duration-150 ${
              isLight ? 'bg-white border-rose-300' : 'bg-slate-900 border-rose-500/50'
            }`}
          >
            <div className="flex items-start gap-3 mb-4">
              <div
                className={`w-10 h-10 rounded-xl border flex items-center justify-center shrink-0 ${
                  isLight
                    ? 'bg-rose-50 border-rose-200 text-rose-600'
                    : 'bg-rose-500/20 border-rose-500/40 text-rose-400'
                }`}
              >
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div className="flex-1 min-w-0">
                <h3 className={`text-sm font-bold uppercase tracking-wider ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Confirm Session Revocation
                </h3>
                <p className={`text-xs mt-1 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                  Are you sure you want to terminate the active session for principal{' '}
                  <span className={`font-mono font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>
                    [{confirmRevokeUser.username}]
                  </span>{' '}
                  in Cloudflare D1?
                </p>
              </div>
            </div>

            <div
              className={`p-3 rounded-xl border space-y-1.5 text-xs font-mono mb-4 ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/80 border-slate-800'
              }`}
            >
              <div className="flex justify-between">
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Principal:</span>
                <span className={`font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>{confirmRevokeUser.username}</span>
              </div>
              <div className="flex justify-between">
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Assigned Role:</span>
                <span className={isLight ? 'text-purple-700' : 'text-purple-400'}>{confirmRevokeUser.role}</span>
              </div>
              <div className="flex justify-between">
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Base Risk:</span>
                <span
                  className={`tabular-nums ${
                    confirmRevokeUser.base_risk_score >= 50
                      ? isLight
                        ? 'text-rose-700'
                        : 'text-rose-400'
                      : isLight
                      ? 'text-emerald-700'
                      : 'text-emerald-400'
                  }`}
                >
                  {confirmRevokeUser.base_risk_score}%
                </span>
              </div>
              <div className="flex justify-between">
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Token Status:</span>
                <span className={`font-bold ${isLight ? 'text-rose-700' : 'text-rose-400'}`}>WILL BE REVOKED IMMEDIATELY</span>
              </div>
            </div>

            <div
              className={`text-[11px] mb-4 border p-2.5 rounded-lg flex items-center gap-2 ${
                isLight
                  ? 'text-rose-900 bg-rose-50 border-rose-200'
                  : 'text-slate-300 bg-rose-500/10 border-rose-500/20'
              }`}
            >
              <AlertTriangle className={`w-4 h-4 shrink-0 ${isLight ? 'text-rose-600' : 'text-rose-400'}`} />
              <span>
                All subsequent API requests using this user's current Bearer token will immediately fail with HTTP 403 Forbidden.
              </span>
            </div>

            <div className="flex items-center justify-end gap-2.5">
              <button
                type="button"
                onClick={() => setConfirmRevokeUser(null)}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  isLight
                    ? 'bg-slate-200 hover:bg-slate-300 text-slate-800'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                }`}
              >
                Cancel
              </button>
              <button
                type="button"
                id="btn-confirm-revoke-session"
                disabled={revokingUser === confirmRevokeUser.username}
                onClick={async () => {
                  const targetUsername = confirmRevokeUser.username;
                  setRevokingUser(targetUsername);
                  try {
                    await onRevokeSession?.(targetUsername);
                    setRevokedUsersList((prev) => new Set(prev).add(targetUsername));
                    setRevocationNotice(`Active session for principal [${targetUsername}] terminated in real-time. Token invalidated.`);
                    setTimeout(() => setRevocationNotice(null), 5000);
                  } catch (err: any) {
                    setRevocationNotice(`Revocation failed: ${err?.message || String(err)}`);
                  } finally {
                    setRevokingUser(null);
                    setConfirmRevokeUser(null);
                  }
                }}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white flex items-center gap-1.5 transition-colors shadow-md cursor-pointer disabled:opacity-50"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>{revokingUser === confirmRevokeUser.username ? 'Revoking...' : 'Yes, Revoke Session'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
