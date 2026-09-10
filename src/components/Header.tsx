import React from 'react';
import {
  ShieldCheck,
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
  LayoutGrid
} from 'lucide-react';
import { AuthSession } from '../types.ts';

export type FeatureTabId = 'health' | 'interceptor' | 'audit' | 'iam' | 'architecture' | 'overview';

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
  connectionStatus = 'connected'
}) => {
  const navFeatures = [
    {
      id: 'health' as FeatureTabId,
      label: 'Health & Analytics',
      icon: BarChart3,
      badge: blockedCount > 0 ? `${blockedCount} Blocked` : 'Nominal',
      badgeColor: blockedCount > 0 ? 'bg-rose-500/15 text-rose-400 border-rose-500/30' : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
    },
    {
      id: 'interceptor' as FeatureTabId,
      label: 'Security Interceptor',
      icon: Shield,
      badge: 'Active Sim',
      badgeColor: 'bg-blue-500/15 text-blue-400 border-blue-500/30'
    },
    {
      id: 'audit' as FeatureTabId,
      label: 'Audit Ledger',
      icon: FileText,
      badge: `${logsCount} Events`,
      badgeColor: 'bg-slate-700/60 text-slate-300 border-slate-600'
    },
    {
      id: 'iam' as FeatureTabId,
      label: 'IAM & Access',
      icon: Users,
      badge: `${usersCount} Principals`,
      badgeColor: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30'
    },
    {
      id: 'architecture' as FeatureTabId,
      label: 'Cloud Architecture',
      icon: Cpu,
      badge: 'D1 + Edge',
      badgeColor: 'bg-amber-500/15 text-amber-400 border-amber-500/30'
    },
    {
      id: 'overview' as FeatureTabId,
      label: 'All Modules',
      icon: LayoutGrid,
      badge: 'Unified',
      badgeColor: 'bg-slate-800 text-slate-400 border-slate-700'
    }
  ];

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
                    'bg-slate-800 text-slate-300 border border-slate-700'
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

          <button
            id="btn-clear-logs"
            onClick={onClearLogs}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-rose-400 border border-slate-800 text-xs font-mono transition-colors"
            title="Clear live security audit logs"
          >
            <Trash2 className="w-3.5 h-3.5 text-rose-400/80" />
            <span>Clear Logs</span>
          </button>

          <button
            id="btn-reset-db"
            onClick={onReset}
            disabled={isResetting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 text-xs font-mono transition-colors disabled:opacity-50"
            title="Reset Database to initial state"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-emerald-400 ${isResetting ? 'animate-spin' : ''}`} />
            <span>Reset Baseline</span>
          </button>
        </div>
      </div>

      {/* Feature Line Navigation Bar - Directly below name & details */}
      <nav
        aria-label="Framework Feature Navigation"
        className="mt-4 pt-3 border-t border-slate-800/60 flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-thin"
      >
        <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider pr-2 hidden md:block select-none">
          Modules:
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
    </header>
  );
};
