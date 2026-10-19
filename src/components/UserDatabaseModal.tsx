import React, { useState } from 'react';
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
  KeyRound
} from 'lucide-react';
import { User, UserApprovalStatus } from '../types.ts';

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
  onSelectUserForLogin?: (user: User) => void;
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
  onSelectUserForLogin
}) => {
  const [showAddForm, setShowAddForm] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | UserApprovalStatus>('ALL');
  const [roleFilter, setRoleFilter] = useState<'ALL' | 'Admin' | 'Developer' | 'Guest'>('ALL');
  const [riskFilter, setRiskFilter] = useState<'ALL' | 'CRITICAL' | 'ELEVATED' | 'MODERATE' | 'NOMINAL'>('ALL');
  const [sortBy, setSortBy] = useState<'name' | 'risk_desc' | 'risk_asc' | 'status'>('name');

  // New user form state
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('ZeroTrust_2026');
  const [newRole, setNewRole] = useState<'Admin' | 'Developer' | 'Guest'>('Developer');
  const [newDept, setNewDept] = useState('Engineering & Cloud Ops');
  const [newRisk, setNewRisk] = useState<number>(20);
  const [newStatus, setNewStatus] = useState<UserApprovalStatus>('APPROVED');
  const [newJustification, setNewJustification] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim()) return;
    setIsSubmitting(true);
    setActionError(null);
    try {
      await onAddUser({
        username: newUsername.trim(),
        password: newPassword || 'ZeroTrust_2026',
        role: newRole,
        base_risk_score: newRisk,
        department: newDept,
        status: newStatus,
        requestJustification: newJustification || 'Manual creation via User Database Manager'
      });
      setNewUsername('');
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

  const filteredUsers = users.filter((u) => {
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
  }).sort((a, b) => {
    if (sortBy === 'risk_desc') return b.base_risk_score - a.base_risk_score;
    if (sortBy === 'risk_asc') return a.base_risk_score - b.base_risk_score;
    if (sortBy === 'status') return a.status.localeCompare(b.status);
    return a.username.localeCompare(b.username);
  });

  const pendingCount = users.filter((u) => u.status === 'PENDING_APPROVAL').length;
  const approvedCount = users.filter((u) => u.status === 'APPROVED').length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-sans text-slate-200">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold text-white tracking-tight">
                  Enterprise User Database &amp; Saved Logins
                </h3>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {users.length} Total Saved
                </span>
                {pendingCount > 0 && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 font-semibold">
                    {pendingCount} Pending Verification
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Manage all registered logins, view approval clearance status, and provision multi-user identities.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              title="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="p-4 border-b border-slate-800/80 bg-slate-900/40 flex flex-col gap-3">
          {/* Top Risk Visual Spectrum Bar */}
          <div className="p-2.5 bg-slate-950/80 border border-slate-800/80 rounded-xl">
            <div className="flex items-center justify-between text-[11px] mb-1.5">
              <span className="text-slate-400 font-semibold flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
                Identity Risk Spectrum Distribution
              </span>
              <span className="text-slate-500 text-[10px]">
                {users.length} Registered Identities
              </span>
            </div>
            {/* Visual multi-segmented bar */}
            <div className="h-2 w-full rounded-full overflow-hidden flex bg-slate-900 border border-slate-800">
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
            {/* Quick Filter Clickable Metrics */}
            <div className="flex items-center gap-3 mt-2 text-[10px] text-slate-400 flex-wrap">
              <button
                type="button"
                onClick={() => setRiskFilter(riskFilter === 'NOMINAL' ? 'ALL' : 'NOMINAL')}
                className={`flex items-center gap-1 hover:text-white transition-colors ${riskFilter === 'NOMINAL' ? 'text-emerald-300 font-bold' : ''}`}
              >
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                Nominal: {userRiskStats.nominal}
              </button>
              <button
                type="button"
                onClick={() => setRiskFilter(riskFilter === 'MODERATE' ? 'ALL' : 'MODERATE')}
                className={`flex items-center gap-1 hover:text-white transition-colors ${riskFilter === 'MODERATE' ? 'text-cyan-300 font-bold' : ''}`}
              >
                <span className="w-2 h-2 rounded-full bg-cyan-500" />
                Moderate: {userRiskStats.moderate}
              </button>
              <button
                type="button"
                onClick={() => setRiskFilter(riskFilter === 'ELEVATED' ? 'ALL' : 'ELEVATED')}
                className={`flex items-center gap-1 hover:text-white transition-colors ${riskFilter === 'ELEVATED' ? 'text-amber-300 font-bold' : ''}`}
              >
                <span className="w-2 h-2 rounded-full bg-amber-400" />
                Elevated: {userRiskStats.elevated}
              </button>
              <button
                type="button"
                onClick={() => setRiskFilter(riskFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
                className={`flex items-center gap-1 hover:text-white transition-colors ${riskFilter === 'CRITICAL' ? 'text-rose-300 font-bold' : ''}`}
              >
                <span className="w-2 h-2 rounded-full bg-rose-500" />
                Critical: {userRiskStats.critical}
              </button>
              {riskFilter !== 'ALL' && (
                <button
                  type="button"
                  onClick={() => setRiskFilter('ALL')}
                  className="text-blue-400 hover:underline text-[10px] ml-auto"
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
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search username, department, or role..."
                  className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50"
                />
              </div>

              {/* Status Filter */}
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as any)}
                className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500"
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
                className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500"
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
                className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500"
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
                className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500"
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
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium flex items-center gap-1.5 transition-colors"
              title="Populate test corporate users in database"
            >
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              <span>Seed Enterprise Users</span>
            </button>

            <button
              type="button"
              onClick={() => setShowAddForm(!showAddForm)}
              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors"
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
            className="p-4 bg-slate-950/80 border-b border-slate-800 animate-in slide-in-from-top-2 duration-150"
          >
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
                <UserPlus className="w-3.5 h-3.5 text-blue-400" />
                Register New Identity into Database
              </h4>
              <span className="text-[11px] text-slate-400">
                Saves login credentials and sets initial clearance
              </span>
            </div>

            {actionError && (
              <div className="p-2 mb-3 rounded bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5 shrink-0 text-rose-400" />
                <span>{actionError}</span>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-medium">Username *</label>
                <input
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g. devops_elena"
                  className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Password</label>
                <input
                  type="text"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="ZeroTrust_2026"
                  className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Role Clearance</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as any)}
                  className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="Developer">Developer (Tier 1 &amp; 2)</option>
                  <option value="Admin">Admin (Full Control)</option>
                  <option value="Guest">Guest (Read Telemetry Only)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Department / Team</label>
                <input
                  type="text"
                  value={newDept}
                  onChange={(e) => setNewDept(e.target.value)}
                  placeholder="e.g. Threat Intelligence"
                  className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">
                  Base Threat Score ({newRisk}%)
                </label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  step="5"
                  value={newRisk}
                  onChange={(e) => setNewRisk(Number(e.target.value))}
                  className="w-full accent-blue-500 h-2 bg-slate-800 rounded-lg cursor-pointer mt-1"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Initial Approval Status</label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value as any)}
                  className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="APPROVED">APPROVED (Immediate Clearance)</option>
                  <option value="PENDING_APPROVAL">PENDING_APPROVAL (Gated for Verification)</option>
                </select>
              </div>

              <div className="sm:col-span-2 md:col-span-3">
                <label className="block text-slate-400 mb-1 font-medium">
                  Access Justification / Note (Optional)
                </label>
                <input
                  type="text"
                  value={newJustification}
                  onChange={(e) => setNewJustification(e.target.value)}
                  placeholder="e.g. SRE contractor for edge pipeline deployments"
                  className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-colors"
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
              <Users className="w-8 h-8 mx-auto mb-2 text-slate-600 opacity-60" />
              <p>No identities matched your filter query.</p>
              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setStatusFilter('ALL');
                  setRoleFilter('ALL');
                }}
                className="mt-2 text-blue-400 hover:underline text-xs"
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

                return (
                  <div
                    key={user.id || user.username}
                    className="p-3.5 rounded-xl border border-slate-800/80 bg-slate-950/50 hover:border-slate-700/80 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                  >
                    {/* User Identity Info */}
                    <div className="flex items-start gap-3 min-w-0">
                      <div
                        className={`w-9 h-9 rounded-xl flex items-center justify-center font-mono font-bold text-xs shrink-0 border ${
                          user.role === 'Admin'
                            ? 'bg-purple-950/40 border-purple-500/30 text-purple-300'
                            : user.role === 'Developer'
                            ? 'bg-blue-950/40 border-blue-500/30 text-blue-300'
                            : 'bg-slate-800 border-slate-700 text-slate-300'
                        }`}
                      >
                        {user.username.slice(0, 2).toUpperCase()}
                      </div>

                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-white font-mono text-sm">
                            {user.username}
                          </span>
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                              user.role === 'Admin'
                                ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                                : user.role === 'Developer'
                                ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                                : 'bg-slate-800 text-slate-400 border-slate-700'
                            }`}
                          >
                            {user.role}
                          </span>

                          {/* Approval Status Badge */}
                          {isApproved && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                              <CheckCircle2 className="w-2.5 h-2.5" />
                              Approved
                            </span>
                          )}
                          {isPending && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 flex items-center gap-1 font-semibold animate-pulse">
                              <Clock className="w-2.5 h-2.5" />
                              Pending Verification
                            </span>
                          )}
                          {isRejected && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30 flex items-center gap-1">
                              <XCircle className="w-2.5 h-2.5" />
                              Rejected
                            </span>
                          )}
                          {isSuspended && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30 flex items-center gap-1">
                              <ShieldAlert className="w-2.5 h-2.5" />
                              Suspended
                            </span>
                          )}

                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/30 flex items-center gap-1">
                            <Smartphone className="w-2.5 h-2.5 text-blue-400" />
                            MFA Active
                          </span>
                        </div>

                        <div className="flex items-center gap-3 text-[11px] text-slate-400 mt-1 flex-wrap">
                          {user.department && (
                            <span className="flex items-center gap-1">
                              <Building2 className="w-3 h-3 text-slate-500" />
                              {user.department}
                            </span>
                          )}
                          {/* Visual Risk Meter and Score */}
                          <div className="flex items-center gap-2">
                            <span className="font-mono">
                              Risk:{' '}
                              <span
                                className={
                                  user.base_risk_score >= 75
                                    ? 'text-rose-400 font-bold'
                                    : user.base_risk_score >= 50
                                    ? 'text-amber-400 font-bold'
                                    : user.base_risk_score >= 25
                                    ? 'text-cyan-400 font-bold'
                                    : 'text-emerald-400 font-bold'
                                }
                              >
                                {user.base_risk_score}%
                              </span>
                            </span>

                            {/* Mini visual meter */}
                            <div className="w-16 h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800 hidden sm:block">
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
                              className={`text-[9px] px-1.5 py-0.2 rounded font-mono font-bold uppercase tracking-wider ${
                                user.base_risk_score >= 75
                                  ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                                  : user.base_risk_score >= 50
                                  ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                                  : user.base_risk_score >= 25
                                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                                  : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
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
                          {user.approvedBy && (
                            <span className="text-slate-500 font-mono text-[10px]">
                              Cleared by: {user.approvedBy}
                            </span>
                          )}
                        </div>

                        {user.requestJustification && (
                          <p className="text-[11px] text-slate-400 mt-1 italic border-l-2 border-slate-700 pl-2">
                            "{user.requestJustification}"
                          </p>
                        )}
                      </div>
                    </div>

                    {/* Action Controls */}
                    <div className="flex items-center gap-1.5 shrink-0 self-end sm:self-center">
                      {isPending && (
                        <>
                          <button
                            type="button"
                            onClick={() => onApproveUser(user.username)}
                            className="px-2.5 py-1 text-xs font-semibold rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 transition-colors"
                            title="Verify and Approve user for login"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Approve</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => onRejectUser(user.username)}
                            className="px-2.5 py-1 text-xs font-semibold rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30 flex items-center gap-1 transition-colors"
                            title="Reject user request"
                          >
                            <XCircle className="w-3.5 h-3.5 text-rose-400" />
                            <span>Reject</span>
                          </button>
                        </>
                      )}

                      {isApproved && onSelectUserForLogin && (
                        <button
                          type="button"
                          onClick={() => {
                            onSelectUserForLogin(user);
                            onClose();
                          }}
                          className="px-2.5 py-1 text-xs font-medium rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 flex items-center gap-1 transition-colors"
                          title="Log in directly as this approved user"
                        >
                          <UserCheck className="w-3.5 h-3.5 text-blue-400" />
                          <span>Login As</span>
                        </button>
                      )}

                      {user.username !== 'secops_admin' && (
                        <button
                          type="button"
                          onClick={() => onDeleteUser(user.username)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-950/40 transition-colors"
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

        {/* Modal Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
          <span className="font-mono text-[11px]">
            Cloudflare D1 SQLite &amp; Edge IAM Engine
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close Directory
          </button>
        </div>
      </div>
    </div>
  );
};
