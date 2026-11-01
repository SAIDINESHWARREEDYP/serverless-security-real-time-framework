import React, { useState, useEffect, useMemo } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
  Key,
  Lock,
  Unlock,
  AlertTriangle,
  History,
  Grid,
  Search,
  Check,
  X,
  UserCheck,
  UserX,
  FileText,
  Clock,
  ArrowRight,
  RefreshCw,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { User } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';

interface RbacManagementModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUserRole: string;
  currentUsername: string;
  users: User[];
  onRoleAssigned?: () => void;
}

interface RoleEntity {
  id: string;
  name: string;
  description: string;
  clearance_tier: number;
}

interface PermissionEntity {
  id: string;
  name: string;
  resource: string;
  action: string;
  description: string;
  category: 'IDENTITY' | 'POLICY' | 'EXECUTION' | 'TELEMETRY' | 'SECURITY';
}

interface AccessDeniedLog {
  id: string;
  username: string;
  role: string;
  endpoint: string;
  required_permission: string;
  violation_type: string;
  timestamp: string;
  ip_address?: string;
}

interface ChangeHistoryLog {
  id: string;
  target_user: string;
  previous_role: string;
  new_role: string;
  changed_by: string;
  reason: string;
  timestamp: string;
}

export const RbacManagementModal: React.FC<RbacManagementModalProps> = ({
  isOpen,
  onClose,
  currentUserRole,
  currentUsername,
  users,
  onRoleAssigned
}) => {
  const { isLight } = useTheme();
  const [activeTab, setActiveTab] = useState<'matrix' | 'directory' | 'detail' | 'roles' | 'denied' | 'history'>('matrix');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);

  // RBAC Data fetched from backend API
  const [roles, setRoles] = useState<RoleEntity[]>([]);
  const [permissions, setPermissions] = useState<PermissionEntity[]>([]);
  const [matrix, setMatrix] = useState<Record<string, string[]>>({});
  const [accessDeniedLogs, setAccessDeniedLogs] = useState<AccessDeniedLog[]>([]);
  const [changeHistory, setChangeHistory] = useState<ChangeHistoryLog[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Role assignment form state
  const [assignTargetUser, setAssignTargetUser] = useState<string>('');
  const [assignNewRole, setAssignNewRole] = useState<string>('Developer');
  const [assignReason, setAssignReason] = useState<string>('');
  const [isAssigning, setIsAssigning] = useState(false);

  // Directory search & filtering
  const [dirSearch, setDirSearch] = useState('');
  const [dirRoleFilter, setDirRoleFilter] = useState('ALL');

  // Matrix category filter
  const [matrixCategory, setMatrixCategory] = useState<'ALL' | 'IDENTITY' | 'POLICY' | 'EXECUTION' | 'TELEMETRY' | 'SECURITY'>('ALL');

  // Fetch Matrix, Roles, Permissions and Logs from Server
  const fetchRbacData = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const token = localStorage.getItem('auth_jwt_token');
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const [matrixRes, historyRes, deniedRes] = await Promise.all([
        fetch('/api/v1/rbac/matrix', { headers }),
        fetch('/api/v1/rbac/history', { headers }).catch(() => null),
        fetch('/api/v1/rbac/access-denied', { headers }).catch(() => null)
      ]);

      if (matrixRes.ok) {
        const data = await matrixRes.json();
        setMatrix(data.matrix || {});
        setRoles(data.roles || []);
        setPermissions(data.permissions || []);
      }

      if (historyRes && historyRes.ok) {
        const histData = await historyRes.json();
        setChangeHistory(histData.history || []);
      }

      if (deniedRes && deniedRes.ok) {
        const denData = await deniedRes.json();
        setAccessDeniedLogs(denData.history || []);
      }
    } catch (err: any) {
      setErrorMsg('Failed to load RBAC metadata from server');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchRbacData();
    }
  }, [isOpen]);

  const handleAssignRole = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!assignTargetUser) return;
    setIsAssigning(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const token = localStorage.getItem('auth_jwt_token');
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/v1/rbac/assign', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          targetUsername: assignTargetUser,
          newRole: assignNewRole,
          reason: assignReason || 'Zero-trust clearance review'
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.detail || 'Role assignment failed');
      }

      setSuccessMsg(`Principal [${assignTargetUser}] clearance elevated/reassigned to [${assignNewRole}].`);
      setAssignReason('');
      fetchRbacData();
      if (onRoleAssigned) onRoleAssigned();
    } catch (err: any) {
      setErrorMsg(err.message || 'Privilege escalation prevented');
    } finally {
      setIsAssigning(false);
    }
  };

  // Filtered users for directory
  const filteredUsers = useMemo(() => {
    return users.filter((u) => {
      if (dirRoleFilter !== 'ALL' && u.role !== dirRoleFilter) return false;
      if (dirSearch.trim()) {
        const q = dirSearch.toLowerCase();
        return u.username.toLowerCase().includes(q) || (u.department && u.department.toLowerCase().includes(q));
      }
      return true;
    });
  }, [users, dirSearch, dirRoleFilter]);

  // Filtered permissions for matrix
  const filteredPermissions = useMemo(() => {
    if (matrixCategory === 'ALL') return permissions;
    return permissions.filter((p) => p.category === matrixCategory);
  }, [permissions, matrixCategory]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 overflow-y-auto font-mono">
      {/* Glossy Backdrop */}
      <div
        className="fixed inset-0 bg-slate-950/80 backdrop-blur-md transition-opacity duration-300"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Main Modal Dialog */}
      <div
        className={`relative w-full max-w-5xl rounded-3xl border shadow-2xl overflow-hidden z-10 flex flex-col max-h-[90vh] transition-all ${
          isLight
            ? 'bg-white border-slate-200 text-slate-800'
            : 'bg-[#0a0f1d] border-slate-800/90 text-slate-100'
        }`}
        role="dialog"
        aria-modal="true"
        aria-label="Role-Based Access Control and Permissions Management"
      >
        {/* Modal Header */}
        <div className={`p-5 sm:p-6 border-b flex items-center justify-between shrink-0 ${
          isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#0d1527] border-slate-800'
        }`}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-500 shadow-xs">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base sm:text-lg font-bold tracking-tight">
                  Identity &amp; Access Governance (RBAC)
                </h2>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/30">
                  6 Canonical Roles • 21 Permissions
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Centralized server-enforced authorization, permissions matrix, and privilege escalation guards
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={fetchRbacData}
              disabled={isLoading}
              className={`p-2 rounded-xl border transition-all ${
                isLight ? 'bg-white hover:bg-slate-100 border-slate-200' : 'bg-slate-900 hover:bg-slate-800 border-slate-800'
              }`}
              title="Refresh RBAC metadata"
            >
              <RefreshCw className={`w-4 h-4 text-slate-400 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className={`p-2 rounded-xl border transition-all ${
                isLight ? 'bg-white hover:bg-slate-100 border-slate-200' : 'bg-slate-900 hover:bg-slate-800 border-slate-800'
              }`}
              aria-label="Close modal"
            >
              <X className="w-5 h-5 text-slate-400" />
            </button>
          </div>
        </div>

        {/* Global Alert Notification */}
        {errorMsg && (
          <div className="px-5 py-3 bg-rose-500/15 border-b border-rose-500/30 text-rose-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button type="button" onClick={() => setErrorMsg(null)} className="text-slate-400 hover:text-white">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {successMsg && (
          <div className="px-5 py-3 bg-emerald-500/15 border-b border-emerald-500/30 text-emerald-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Check className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{successMsg}</span>
            </div>
            <button type="button" onClick={() => setSuccessMsg(null)} className="text-slate-400 hover:text-white">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className={`px-5 pt-3 border-b flex items-center gap-2 overflow-x-auto shrink-0 ${
          isLight ? 'bg-slate-100/70 border-slate-200' : 'bg-slate-900/60 border-slate-800/80'
        }`}>
          <button
            type="button"
            onClick={() => setActiveTab('matrix')}
            className={`px-4 py-2 text-xs font-bold rounded-t-xl transition-all border-b-2 flex items-center gap-1.5 ${
              activeTab === 'matrix'
                ? isLight
                  ? 'bg-white text-blue-600 border-blue-600'
                  : 'bg-[#0a0f1d] text-blue-400 border-blue-400'
                : 'text-slate-400 border-transparent hover:text-white'
            }`}
          >
            <Grid className="w-3.5 h-3.5" />
            <span>Permissions Matrix (6×21)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('directory')}
            className={`px-4 py-2 text-xs font-bold rounded-t-xl transition-all border-b-2 flex items-center gap-1.5 ${
              activeTab === 'directory'
                ? isLight
                  ? 'bg-white text-blue-600 border-blue-600'
                  : 'bg-[#0a0f1d] text-blue-400 border-blue-400'
                : 'text-slate-400 border-transparent hover:text-white'
            }`}
          >
            <Users className="w-3.5 h-3.5" />
            <span>User Directory ({users.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('roles')}
            className={`px-4 py-2 text-xs font-bold rounded-t-xl transition-all border-b-2 flex items-center gap-1.5 ${
              activeTab === 'roles'
                ? isLight
                  ? 'bg-white text-blue-600 border-blue-600'
                  : 'bg-[#0a0f1d] text-blue-400 border-blue-400'
                : 'text-slate-400 border-transparent hover:text-white'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Role Specifications ({roles.length || 6})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('denied')}
            className={`px-4 py-2 text-xs font-bold rounded-t-xl transition-all border-b-2 flex items-center gap-1.5 ${
              activeTab === 'denied'
                ? isLight
                  ? 'bg-white text-rose-600 border-rose-600'
                  : 'bg-[#0a0f1d] text-rose-400 border-rose-400'
                : 'text-slate-400 border-transparent hover:text-white'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
            <span>Access-Denied History ({accessDeniedLogs.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('history')}
            className={`px-4 py-2 text-xs font-bold rounded-t-xl transition-all border-b-2 flex items-center gap-1.5 ${
              activeTab === 'history'
                ? isLight
                  ? 'bg-white text-blue-600 border-blue-600'
                  : 'bg-[#0a0f1d] text-blue-400 border-blue-400'
                : 'text-slate-400 border-transparent hover:text-white'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>Permission Change Audit ({changeHistory.length})</span>
          </button>
        </div>

        {/* Tab Content Panes */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-6 space-y-6">
          {/* TAB 1: 6x21 PERMISSIONS MATRIX GRID */}
          {activeTab === 'matrix' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                  <h3 className="text-sm font-bold tracking-tight">Canonical Role-Permission Enforcement Matrix</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Server evaluates every API invocation against this matrix. Frontend view is decorative; backend enforces unconditionally.
                  </p>
                </div>

                {/* Category filter buttons */}
                <div className={`flex items-center gap-1 p-1 rounded-xl border text-[11px] ${
                  isLight ? 'bg-slate-100 border-slate-200' : 'bg-slate-900 border-slate-800'
                }`}>
                  {(['ALL', 'IDENTITY', 'POLICY', 'EXECUTION', 'SECURITY', 'TELEMETRY'] as const).map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setMatrixCategory(cat)}
                      className={`px-2.5 py-1 rounded-lg transition-all font-semibold ${
                        matrixCategory === cat
                          ? isLight ? 'bg-white text-blue-600 shadow-xs' : 'bg-blue-600 text-white shadow-xs'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>

              {/* Scrollable Matrix Table */}
              <div className="rounded-2xl border border-slate-800 overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className={isLight ? 'bg-slate-100/80 text-slate-700' : 'bg-slate-900/90 text-slate-300'}>
                      <th className="p-3 font-bold border-b border-r border-slate-800 sticky left-0 z-10 min-w-[200px] bg-inherit">
                        Granular Permission
                      </th>
                      <th className="p-3 font-bold border-b border-r border-slate-800 text-center min-w-[120px]">
                        Category
                      </th>
                      <th className="p-3 font-bold border-b border-r border-slate-800 text-center text-purple-400 min-w-[130px]">
                        Super Admin
                      </th>
                      <th className="p-3 font-bold border-b border-r border-slate-800 text-center text-blue-400 min-w-[130px]">
                        Security Admin
                      </th>
                      <th className="p-3 font-bold border-b border-r border-slate-800 text-center text-cyan-400 min-w-[130px]">
                        Security Analyst
                      </th>
                      <th className="p-3 font-bold border-b border-r border-slate-800 text-center text-indigo-400 min-w-[110px]">
                        Developer
                      </th>
                      <th className="p-3 font-bold border-b border-r border-slate-800 text-center text-emerald-400 min-w-[100px]">
                        Auditor
                      </th>
                      <th className="p-3 font-bold border-b border-slate-800 text-center text-slate-400 min-w-[90px]">
                        Viewer
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredPermissions.map((perm) => {
                      const superAdminHas = matrix['Super Administrator']?.includes(perm.name) ?? true;
                      const secAdminHas = matrix['Security Administrator']?.includes(perm.name) ?? false;
                      const analystHas = matrix['Security Analyst']?.includes(perm.name) ?? false;
                      const devHas = matrix['Developer']?.includes(perm.name) ?? false;
                      const auditorHas = matrix['Auditor']?.includes(perm.name) ?? false;
                      const viewerHas = matrix['Viewer']?.includes(perm.name) ?? false;

                      return (
                        <tr key={perm.id} className={isLight ? 'hover:bg-slate-50' : 'hover:bg-slate-900/40'}>
                          <td className="p-3 border-r border-slate-800 sticky left-0 z-10 bg-inherit min-w-[200px]">
                            <div className="font-bold text-slate-200 dark:text-slate-100">{perm.name}</div>
                            <div className="text-[10px] text-slate-500 line-clamp-1">{perm.description}</div>
                          </td>
                          <td className="p-3 border-r border-slate-800 text-center text-[10px] text-slate-400">
                            <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700">
                              {perm.category}
                            </span>
                          </td>
                          <td className="p-3 border-r border-slate-800 text-center">
                            {superAdminHas ? (
                              <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-purple-500/20 text-purple-400 font-bold">✓</span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </td>
                          <td className="p-3 border-r border-slate-800 text-center">
                            {secAdminHas ? (
                              <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 font-bold">✓</span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </td>
                          <td className="p-3 border-r border-slate-800 text-center">
                            {analystHas ? (
                              <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 font-bold">✓</span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </td>
                          <td className="p-3 border-r border-slate-800 text-center">
                            {devHas ? (
                              <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-indigo-500/20 text-indigo-400 font-bold">✓</span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </td>
                          <td className="p-3 border-r border-slate-800 text-center">
                            {auditorHas ? (
                              <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 font-bold">✓</span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </td>
                          <td className="p-3 text-center">
                            {viewerHas ? (
                              <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-slate-700/50 text-slate-300 font-bold">✓</span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 2: USER DIRECTORY & ROLE ASSIGNMENT */}
          {activeTab === 'directory' && (
            <div className="space-y-5">
              {/* Directory Filter Bar */}
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div className={`flex items-center gap-2 px-3 py-2 rounded-xl border text-xs w-full sm:max-w-xs ${
                  isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900 border-slate-800'
                }`}>
                  <Search className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  <input
                    type="text"
                    value={dirSearch}
                    onChange={(e) => setDirSearch(e.target.value)}
                    placeholder="Search principal or department..."
                    className="w-full bg-transparent border-none outline-none text-xs"
                  />
                  {dirSearch && <button type="button" onClick={() => setDirSearch('')}>✕</button>}
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">Filter Role:</span>
                  <select
                    value={dirRoleFilter}
                    onChange={(e) => setDirRoleFilter(e.target.value)}
                    className={`text-xs px-2.5 py-1.5 rounded-xl border outline-none ${
                      isLight ? 'bg-white border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-800 text-slate-200'
                    }`}
                  >
                    <option value="ALL">All Roles ({users.length})</option>
                    <option value="Admin">Super Administrator / Admin</option>
                    <option value="Security Administrator">Security Administrator</option>
                    <option value="Security Analyst">Security Analyst</option>
                    <option value="Developer">Developer</option>
                    <option value="Auditor">Auditor</option>
                    <option value="Guest">Viewer / Guest</option>
                  </select>
                </div>
              </div>

              {/* Principal Cards Roster */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {filteredUsers.map((user) => {
                  const isCurrent = user.username.toLowerCase() === currentUsername.toLowerCase();
                  return (
                    <div
                      key={user.id}
                      className={`p-4 rounded-2xl border transition-all flex flex-col justify-between gap-3 ${
                        isLight
                          ? 'bg-slate-50/70 border-slate-200 hover:border-slate-300'
                          : 'bg-slate-900/40 border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2.5">
                            <div className="w-8 h-8 rounded-xl bg-blue-600/20 text-blue-400 border border-blue-500/30 font-bold flex items-center justify-center text-xs">
                              {user.username[0]?.toUpperCase()}
                            </div>
                            <div>
                              <div className="text-xs font-bold flex items-center gap-1.5">
                                <span>{user.username}</span>
                                {isCurrent && (
                                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                                    You
                                  </span>
                                )}
                              </div>
                              <div className="text-[10px] text-slate-500">
                                {user.department || 'Cloud Engineering'}
                              </div>
                            </div>
                          </div>

                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                            user.role === 'Admin' || user.role === 'Super Administrator'
                              ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                              : user.role === 'Security Administrator'
                              ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                              : user.role === 'Developer'
                              ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30'
                              : 'bg-slate-800 text-slate-300 border-slate-700'
                          }`}>
                            {user.role}
                          </span>
                        </div>

                        <div className="grid grid-cols-3 gap-2 mt-3 pt-3 border-t border-slate-800/60 text-[11px]">
                          <div>
                            <span className="text-slate-500 text-[10px] block">Base Risk</span>
                            <span className={`font-bold ${
                              user.base_risk_score >= 75 ? 'text-rose-400' : user.base_risk_score >= 35 ? 'text-amber-400' : 'text-emerald-400'
                            }`}>
                              {user.base_risk_score}%
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500 text-[10px] block">Clearance</span>
                            <span className="text-slate-300">
                              {user.status || 'APPROVED'}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500 text-[10px] block">MFA Gate</span>
                            <span className={user.mfa_enabled ? 'text-emerald-400' : 'text-amber-400'}>
                              {user.mfa_enabled ? 'Enforced' : 'Optional'}
                            </span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/40">
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedUser(user);
                            setActiveTab('detail');
                          }}
                          className="text-[11px] text-blue-400 hover:text-blue-300 flex items-center gap-1 font-semibold"
                        >
                          <span>Inspect Attributes</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>

                        <button
                          type="button"
                          onClick={() => {
                            setAssignTargetUser(user.username);
                            setAssignNewRole(user.role === 'Developer' ? 'Security Analyst' : 'Developer');
                            setActiveTab('roles');
                          }}
                          className={`text-[10px] font-mono font-medium px-2.5 py-1 rounded-lg border transition-all ${
                            isLight
                              ? 'bg-white hover:bg-slate-100 text-slate-800 border-slate-300 shadow-xs'
                              : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                          }`}
                        >
                          Modify Clearance
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 3: USER DETAIL VIEW */}
          {activeTab === 'detail' && selectedUser && (
            <div className="space-y-5">
              <button
                type="button"
                onClick={() => setActiveTab('directory')}
                className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 mb-2"
              >
                ← Back to User Directory
              </button>

              <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/40 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 rounded-2xl bg-blue-600/20 text-blue-400 border border-blue-500/30 font-bold flex items-center justify-center text-lg">
                      {selectedUser.username[0]?.toUpperCase()}
                    </div>
                    <div>
                      <h3 className="text-base font-bold">{selectedUser.username}</h3>
                      <p className="text-xs text-slate-400">{selectedUser.department || 'Cloud Engineering & Infrastructure'}</p>
                    </div>
                  </div>

                  <span className="text-xs font-bold px-3 py-1 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">
                    Role: {selectedUser.role}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs pt-3 border-t border-slate-800">
                  <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">Base Risk Index</span>
                    <span className="text-base font-bold text-amber-400">{selectedUser.base_risk_score}%</span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">Approval Status</span>
                    <span className="text-base font-bold text-emerald-400">{selectedUser.status || 'APPROVED'}</span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">MFA Enforcement</span>
                    <span className="text-base font-bold text-blue-400">{selectedUser.mfa_enabled ? 'Active TOTP' : 'Disabled'}</span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">Identifier</span>
                    <span className="text-xs font-mono text-slate-300 truncate block">{selectedUser.id}</span>
                  </div>
                </div>

                <div className="space-y-2 pt-2">
                  <h4 className="text-xs font-bold text-slate-300">Active Permissions Assigned</h4>
                  <div className="flex flex-wrap gap-1.5">
                    {(matrix[selectedUser.role] || matrix['Developer'] || []).map((perm) => (
                      <span key={perm} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {perm}
                      </span>
                    ))}
                  </div>
                </div>

                {selectedUser.requestJustification && (
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                    <span className="text-[10px] text-slate-400 font-bold block mb-1">Onboarding Justification:</span>
                    <p className="text-slate-300 italic">{selectedUser.requestJustification}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: ROLE SPECIFICATIONS & SAFE ROLE REASSIGNMENT */}
          {activeTab === 'roles' && (
            <div className="space-y-6">
              {/* Role Assignment Form with Privilege Escalation Prevention */}
              <div className="p-5 rounded-2xl border border-blue-500/30 bg-blue-950/10 space-y-4">
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-blue-400" />
                  <h3 className="text-sm font-bold tracking-tight">Privilege-Guarded Role Reassignment</h3>
                </div>
                <p className="text-xs text-slate-400">
                  Enforces strict Zero-Trust rules: self-promotion is blocked, only Super Administrators can grant Super Administrator clearance, and all changes are recorded into the tamper-evident audit ledger.
                </p>

                <form onSubmit={handleAssignRole} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Target Principal</label>
                    <select
                      value={assignTargetUser}
                      onChange={(e) => setAssignTargetUser(e.target.value)}
                      className={`w-full text-xs p-2.5 rounded-xl border outline-none ${
                        isLight ? 'bg-white border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-800 text-slate-200'
                      }`}
                      required
                    >
                      <option value="">Select principal...</option>
                      {users.map((u) => (
                        <option key={u.id} value={u.username}>
                          {u.username} (Current: {u.role})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">New Target Role</label>
                    <select
                      value={assignNewRole}
                      onChange={(e) => setAssignNewRole(e.target.value)}
                      className={`w-full text-xs p-2.5 rounded-xl border outline-none ${
                        isLight ? 'bg-white border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-800 text-slate-200'
                      }`}
                    >
                      <option value="Super Administrator">Super Administrator (Tier 6)</option>
                      <option value="Security Administrator">Security Administrator (Tier 5)</option>
                      <option value="Security Analyst">Security Analyst (Tier 4)</option>
                      <option value="Developer">Developer (Tier 3)</option>
                      <option value="Auditor">Auditor (Tier 2)</option>
                      <option value="Viewer">Viewer (Tier 1)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Reason / Justification</label>
                    <input
                      type="text"
                      value={assignReason}
                      onChange={(e) => setAssignReason(e.target.value)}
                      placeholder="e.g. Quarterly clearance adjustment"
                      className={`w-full text-xs p-2.5 rounded-xl border outline-none ${
                        isLight ? 'bg-white border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-800 text-slate-200'
                      }`}
                    />
                  </div>

                  <div className="sm:col-span-3 flex justify-end">
                    <button
                      type="submit"
                      disabled={isAssigning || !assignTargetUser}
                      className="px-4 py-2 rounded-xl text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50 transition-all flex items-center gap-2"
                    >
                      {isAssigning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                      <span>Apply Role Mutation</span>
                    </button>
                  </div>
                </form>
              </div>

              {/* Roles Breakdown */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                {roles.map((role) => (
                  <div key={role.id} className="p-4 rounded-2xl border border-slate-800 bg-slate-900/40 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-200">{role.name}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-blue-400 border border-slate-700 font-mono">
                        Tier {role.clearance_tier}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{role.description}</p>
                    <div className="text-[10px] text-slate-500 pt-2 border-t border-slate-800/60">
                      Granted Permissions: {matrix[role.name]?.length || 0} entitlements
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 5: ACCESS-DENIED HISTORY */}
          {activeTab === 'denied' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-rose-400">Access-Denied &amp; Security Exception Log</h3>
                  <p className="text-xs text-slate-400">
                    Records every attempt where a caller attempted an unauthorized API, privilege escalation, or IDOR
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-500">
                  {accessDeniedLogs.length} Recorded Incidents
                </span>
              </div>

              <div className="space-y-2.5">
                {accessDeniedLogs.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    No access-denied violations recorded in current active ledger.
                  </div>
                ) : (
                  accessDeniedLogs.map((log) => (
                    <div
                      key={log.id}
                      className="p-3.5 rounded-xl border border-rose-500/30 bg-rose-950/15 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-xs"
                    >
                      <div className="flex items-center gap-2.5">
                        <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0" />
                        <div>
                          <div className="font-bold text-rose-300 flex items-center gap-2">
                            <span>Principal [{log.username}]</span>
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300">
                              {log.violation_type}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400 mt-0.5">
                            Attempted: <span className="font-mono text-slate-200">{log.endpoint}</span> • Required: <span className="font-mono text-amber-300">[{log.required_permission}]</span>
                          </div>
                        </div>
                      </div>

                      <div className="text-[10px] text-slate-500 font-mono text-right shrink-0">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* TAB 6: PERMISSION CHANGE AUDIT */}
          {activeTab === 'history' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold">Role Assignment Change Ledger</h3>
                  <p className="text-xs text-slate-400">
                    Audit trail of all administrative role promotions and reassignments
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-500">
                  {changeHistory.length} Log Entries
                </span>
              </div>

              <div className="space-y-2.5">
                {changeHistory.map((item) => (
                  <div
                    key={item.id}
                    className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/50 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-xs"
                  >
                    <div>
                      <div className="font-bold text-slate-200 flex items-center gap-2">
                        <span>{item.target_user}</span>
                        <span className="text-slate-500">→</span>
                        <span className="text-blue-400 font-semibold">{item.new_role}</span>
                        <span className="text-[10px] text-slate-500">(was {item.previous_role})</span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Changed by <span className="text-slate-300">{item.changed_by}</span> • Reason: {item.reason}
                      </div>
                    </div>

                    <div className="text-[10px] text-slate-500 font-mono text-right shrink-0">
                      {new Date(item.timestamp).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
