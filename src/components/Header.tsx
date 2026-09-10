import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  Trash2,
  Database,
  Cloud,
  UserCheck,
  Lock,
  BarChart3,
  Shield,
  FileText,
  Users,
  Cpu,
  LayoutGrid,
  LogOut,
  Sparkles,
  Fingerprint,
  Code
} from 'lucide-react';
import { AuthSession } from '../types.ts';

export type FeatureTabId = 'admin' | 'guest' | 'health' | 'interceptor' | 'audit' | 'iam' | 'architecture' | 'overview';

interface HeaderProps {
  onReset: () => void;
  onClearLogs: () => void;
  isResetting: boolean;
  onOpenDbModal: () => void;
  onOpenCloudGuide: () => void;
  currentSession: AuthSession | null;
  onOpenAuthModal: () => void;
  activeTab: FeatureTabId;
  onSelectTab: (tab: FeatureTabId) => void;
  logsCount?: number;
  usersCount?: number;
  blockedCount?: number;
  connectionStatus?: 'connected' | 'syncing' | 'reconnecting';
  onQuickSwitchRole?: (role: 'Admin' | 'Developer' | 'Guest') => void;
  onLogout?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onReset,
  onClearLogs,
  isResetting,
  onOpenDbModal,
  onOpenCloudGuide,
  currentSession,
  onOpenAuthModal,
  activeTab,
  onSelectTab,
  logsCount = 0,
  usersCount = 4,
  blockedCount = 0,
  connectionStatus = 'connected',
  onQuickSwitchRole,
  onLogout
}) => {
  // All possible module navigation items
  const allNavFeatures = [
    {
      id: 'admin' as FeatureTabId,
      label: 'Admin Command',
      icon: ShieldAlert,
      badge: 'SecOps',
      badgeColor: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
      allowedRoles: ['Admin']
    },
    {
      id: 'guest' as FeatureTabId,
      label: 'Guest Workspace',
      icon: UserCheck,
      badge: 'Tier 1 Only',
      badgeColor: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
      allowedRoles: ['Guest']
    },
    {
      id: 'interceptor' as FeatureTabId,
      label: currentSession?.user.role === 'Developer' ? 'Developer Workbench' : 'Security Interceptor',
      icon: Shield,
      badge: currentSession?.user.role === 'Developer' ? 'Tier 1 & 2' : 'Active Sim',
      badgeColor: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
      allowedRoles: ['Admin', 'Developer']
    },
    {
      id: 'audit' as FeatureTabId,
      label: currentSession?.user.role === 'Guest' ? 'My Activity' : 'Audit Ledger',
      icon: FileText,
      badge: `${logsCount} Events`,
      badgeColor: 'bg-slate-700/60 text-slate-300 border-slate-600',
      allowedRoles: ['Admin', 'Developer', 'Guest']
    },
    {
      id: 'health' as FeatureTabId,
      label: currentSession?.user.role === 'Guest' ? 'Cluster Status' : 'Health & Analytics',
      icon: BarChart3,
      badge: blockedCount > 0 ? `${blockedCount} Blocked` : 'Nominal',
      badgeColor: blockedCount > 0 ? 'bg-rose-500/15 text-rose-400 border-rose-500/30' : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
      allowedRoles: ['Admin', 'Developer', 'Guest']
    },
    {
      id: 'iam' as FeatureTabId,
      label: 'IAM & Access',
      icon: Users,
      badge: `${usersCount} Principals`,
      badgeColor: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30',
      allowedRoles: ['Admin']
    },
    {
      id: 'architecture' as FeatureTabId,
      label: currentSession?.user.role === 'Developer' ? 'Pipeline Flow' : 'Cloud Architecture',
      icon: Cpu,
      badge: currentSession?.user.role === 'Developer' ? 'Review' : 'D1 + Edge',
      badgeColor: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
      allowedRoles: ['Admin', 'Developer']
    },
    {
      id: 'overview' as FeatureTabId,
      label: 'All Modules',
      icon: LayoutGrid,
      badge: 'Master View',
      badgeColor: 'bg-slate-800 text-slate-400 border-slate-700',
      allowedRoles: ['Admin']
    }
  ];

  // Dynamic role-based nav filter
  const currentRole = currentSession?.user.role;
  const navFeatures = currentRole
    ? allNavFeatures.filter((f) => f.allowedRoles.includes(currentRole))
    : [];

  return (
    <header className="border-b border-slate-800/80 pb-4 mb-6">
      {/* Top Banner: Branding, Status, and Quick Action Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 shadow-sm">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-white text-lg sm:text-xl font-bold tracking-tight flex items-center gap-2">
                Serverless Security Verification Framework
                <span className="hidden sm:inline-block text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
                  Zero Trust v2.4
                </span>
              </h1>
              <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-2 flex-wrap">
                <span>Enterprise Edge Policy Enforcement &amp; Runtime Verification Matrix</span>
                <span className={`inline-block w-1.5 h-1.5 rounded-full ${
                  connectionStatus === 'connected' ? 'bg-emerald-400 animate-pulse' :
                  connectionStatus === 'syncing' ? 'bg-blue-400 animate-ping' :
                  'bg-amber-400 animate-pulse'
                }`}></span>
                <span className={`text-[11px] font-mono ${
                  connectionStatus === 'connected' ? 'text-emerald-400' :
                  connectionStatus === 'syncing' ? 'text-blue-400' :
                  'text-amber-400'
                }`}>
                  {connectionStatus === 'connected' ? 'Edge Interceptor Online' :
                   connectionStatus === 'syncing' ? 'Syncing Pipeline...' :
                   'Edge Connecting...'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Global Action Utility Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Active Session / IAM Trigger */}
          <button
            id="btn-open-auth-modal"
            onClick={onOpenAuthModal}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-mono font-semibold transition-all border shadow-sm ${
              currentSession
                ? 'bg-slate-900/90 hover:bg-slate-800 text-white border-blue-500/40 hover:border-blue-400'
                : 'bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border-amber-500/40'
            }`}
            title="Open IAM Portal - Switch users or sign in with any custom identity"
          >
            {currentSession ? (
              <>
                <UserCheck className="w-4 h-4 text-emerald-400" />
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-200 font-medium">{currentSession.user.username}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                    currentSession.user.role === 'Admin' ? 'bg-purple-900/80 text-purple-200 border border-purple-700/60' :
                    currentSession.user.role === 'Developer' ? 'bg-blue-900/80 text-blue-200 border border-blue-700/60' :
                    'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}>
                    {currentSession.user.role}
                  </span>
                </div>
              </>
            ) : (
              <>
                <Lock className="w-4 h-4 text-amber-400" />
                <span>Sign In / Custom User</span>
              </>
            )}
          </button>

          <button
            id="btn-open-cloud-guide"
            onClick={onOpenCloudGuide}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-500/30 text-xs font-mono font-medium transition-colors shadow-sm"
            title="Open Cloud Deployment & Execution Manual"
          >
            <Cloud className="w-3.5 h-3.5 text-blue-400" />
            <span>Cloud Blueprint</span>
          </button>

          <button
            id="btn-inspect-db"
            onClick={onOpenDbModal}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 text-xs font-mono transition-colors"
            title="Inspect SQL Tables & Rules"
          >
            <Database className="w-3.5 h-3.5 text-slate-400" />
            <span>Schema &amp; Rules</span>
          </button>

          {currentRole === 'Admin' && (
            <>
              <button
                id="btn-clear-logs"
                onClick={onClearLogs}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-rose-400 border border-slate-800 text-xs font-mono transition-colors"
                title="Clear live security audit logs (Admin Only)"
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-400/80" />
                <span>Clear Logs</span>
              </button>

              <button
                id="btn-reset-db"
                onClick={onReset}
                disabled={isResetting}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 text-xs font-mono transition-colors disabled:opacity-50"
                title="Reset Database to initial state (Admin Only)"
              >
                <RefreshCw className={`w-3.5 h-3.5 text-emerald-400 ${isResetting ? 'animate-spin' : ''}`} />
                <span>Reset Baseline</span>
              </button>
            </>
          )}

          {currentSession && onLogout && (
            <button
              id="btn-logout"
              onClick={onLogout}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 hover:text-white border border-rose-800/60 text-xs font-mono transition-colors"
              title="Terminate Active Zero-Trust Session"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign Out</span>
            </button>
          )}
        </div>
      </div>

      {/* QUICK ROLE SIMULATION & SWITCHER BAR */}
      {currentSession && onQuickSwitchRole && (
        <div className="mt-3.5 p-2 bg-slate-950/80 rounded-lg border border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-400 flex items-center gap-1.5 uppercase tracking-wider font-semibold">
              <Fingerprint className="w-3.5 h-3.5 text-blue-400" />
              Active Role Clearance:
            </span>
            <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
              currentRole === 'Admin' ? 'bg-purple-950 text-purple-300 border-purple-700' :
              currentRole === 'Developer' ? 'bg-blue-950 text-blue-300 border-blue-700' :
              'bg-emerald-950 text-emerald-300 border-emerald-700'
            }`}>
              {currentRole === 'Admin' ? 'ADMIN (ALL FEATURES UNLOCKED)' :
               currentRole === 'Developer' ? 'DEVELOPER (TIER 1 & 2 WORKBENCH)' :
               'GUEST (TIER 1 TELEMETRY ONLY)'}
            </span>
          </div>

          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] text-slate-500 uppercase mr-1">1-Click Test Role:</span>
            <button
              type="button"
              onClick={() => onQuickSwitchRole('Guest')}
              className={`px-2.5 py-1 rounded text-[11px] transition-all border ${
                currentRole === 'Guest'
                  ? 'bg-emerald-600 text-white font-bold border-emerald-500 shadow-sm'
                  : 'bg-slate-900 text-slate-400 hover:text-emerald-300 border-slate-800 hover:border-emerald-800'
              }`}
              title="Switch to Guest role (Tier 1 Telemetry only)"
            >
              Guest (alice_guest)
            </button>
            <button
              type="button"
              onClick={() => onQuickSwitchRole('Developer')}
              className={`px-2.5 py-1 rounded text-[11px] transition-all border ${
                currentRole === 'Developer'
                  ? 'bg-blue-600 text-white font-bold border-blue-500 shadow-sm'
                  : 'bg-slate-900 text-slate-400 hover:text-blue-300 border-slate-800 hover:border-blue-800'
              }`}
              title="Switch to Developer role (Tier 1 & 2 Workbench)"
            >
              Developer (bob_dev)
            </button>
            <button
              type="button"
              onClick={() => onQuickSwitchRole('Admin')}
              className={`px-2.5 py-1 rounded text-[11px] transition-all border ${
                currentRole === 'Admin'
                  ? 'bg-purple-600 text-white font-bold border-purple-500 shadow-sm'
                  : 'bg-slate-900 text-slate-400 hover:text-purple-300 border-slate-800 hover:border-purple-800'
              }`}
              title="Switch to Admin role (Executive SecOps & Governance)"
            >
              Admin (secops_admin)
            </button>
          </div>
        </div>
      )}

      {/* Feature Line Navigation Bar - Filtered strictly by role */}
      {navFeatures.length > 0 && (
        <nav
          aria-label="Framework Feature Navigation"
          className="mt-3 pt-2.5 border-t border-slate-800/60 flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-thin"
        >
          <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider pr-2 hidden md:block select-none">
            Permitted Tabs:
          </div>
          {navFeatures.map((feat) => {
            const Icon = feat.icon;
            const isActive = activeTab === feat.id;
            return (
              <button
                key={feat.id}
                id={`nav-tab-${feat.id}`}
                onClick={() => onSelectTab(feat.id)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all whitespace-nowrap border ${
                  isActive
                    ? 'bg-blue-600 text-white border-blue-500 shadow-md shadow-blue-600/20'
                    : 'bg-slate-900/80 hover:bg-slate-800/90 text-slate-300 hover:text-white border-slate-800 hover:border-slate-700'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                <span>{feat.label}</span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                    isActive
                      ? 'bg-blue-700/60 text-blue-100 border-blue-400/40'
                      : feat.badgeColor
                  }`}
                >
                  {feat.badge}
                </span>
              </button>
            );
          })}
        </nav>
      )}
    </header>
  );
};
