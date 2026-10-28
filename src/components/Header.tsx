import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Database,
  Cloud,
  UserCheck,
  Lock,
  LogOut,
  Fingerprint,
  Clock,
  Sun,
  Moon,
  Menu
} from 'lucide-react';
import { AuthSession } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';
import { getSectionMetaForTab } from '../utils/sectionThemes.ts';

export type FeatureTabId =
  | 'admin'
  | 'developer'
  | 'guest'
  | 'ai-threats'
  | 'health'
  | 'interceptor'
  | 'audit'
  | 'iam'
  | 'architecture'
  | 'overview';

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
  onOpenSidebar: () => void;
  logsCount?: number;
  usersCount?: number;
  blockedCount?: number;
  connectionStatus?: 'connected' | 'syncing' | 'reconnecting';
  onQuickSwitchRole?: (role: 'Admin' | 'Developer' | 'Guest') => void;
  onLogout?: () => void;
  onOpenSecurityReport?: () => void;
  pendingApprovalCount?: number;
  onOpenUserDatabase?: () => void;
  onRunCredentialStuffing?: () => void;
  onRunLateralMovementDrill?: () => void;
  onToggleEmergencyLockdown?: () => void;
  isEmergencyLockdownActive?: boolean;
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
  onOpenSidebar,
  logsCount = 0,
  usersCount = 0,
  blockedCount = 0,
  connectionStatus = 'connected',
  onLogout,
  onOpenSecurityReport,
  pendingApprovalCount = 0,
  onOpenUserDatabase,
  onRunCredentialStuffing,
  onRunLateralMovementDrill,
  onToggleEmergencyLockdown,
  isEmergencyLockdownActive = false
}) => {
  const { theme, toggleTheme, isLight } = useTheme();
  const currentRole = currentSession?.user.role || 'Guest';

  // Section metadata for active tab (disciplined section-wise color identity)
  const sectionMeta = getSectionMetaForTab(activeTab);

  return (
    <header className="border-b border-slate-800/80 pb-5 mb-8 space-y-5">
      {/* Top Organization Breadcrumb & System Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono text-slate-400 pb-2 border-b border-slate-800/40">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-slate-300 dark:text-slate-200">Google Cloud Platform</span>
          <span className="text-slate-600">/</span>
          <span>Zero-Trust Enterprise Mesh</span>
          <span className="text-slate-600">/</span>
          <span className="px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700 text-[10px] font-semibold">
            CLUSTER-EAST-01 • ANYCAST 140+ POPS
          </span>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${
              connectionStatus === 'connected' ? 'bg-emerald-500 animate-pulse' :
              connectionStatus === 'syncing' ? 'bg-blue-400 animate-ping' :
              'bg-amber-400 animate-pulse'
            }`}></span>
            <span className={connectionStatus === 'connected' ? 'text-emerald-500 font-semibold' : 'text-slate-400'}>
              {connectionStatus === 'connected' ? 'Edge Mesh Active • 1.4ms' :
               connectionStatus === 'syncing' ? 'Synchronizing Pipeline...' :
               'Reconnecting Gateway...'}
            </span>
          </div>
          <span className="text-slate-700">|</span>
          <span className="text-[11px] text-slate-500">SLA: 99.99% • NIST SP 800-207</span>
        </div>
      </div>

      {/* Main Brand & Action Header */}
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-5">
        <div className="flex items-start sm:items-center gap-3.5">
          {/* PRIMARY MENU TRIGGER: Purely at the last left of the logo (Visible only after login) */}
          {currentSession && (
            <button
              id="btn-open-sidebar"
              type="button"
              onClick={onOpenSidebar}
              className={`p-3 rounded-2xl border shadow-lg transition-all duration-200 hover:scale-105 active:scale-95 shrink-0 flex items-center justify-center cursor-pointer group ${
                isLight
                  ? 'bg-blue-600 hover:bg-blue-700 text-white border-blue-500 shadow-blue-500/25 ring-2 ring-blue-500/10'
                  : 'bg-blue-600 hover:bg-blue-500 text-white border-blue-400/50 shadow-blue-500/30 ring-2 ring-blue-500/20'
              }`}
              title="Open Navigation Menu"
              aria-label="Open Navigation Menu"
            >
              <Menu className="w-6 h-6 transition-transform group-hover:rotate-3" />
            </button>
          )}

          {/* Framework Logo */}
          <div className={`p-3 rounded-2xl border shadow-md transition-transform hover:scale-105 shrink-0 ${
            isLight
              ? 'bg-slate-100 border-slate-200 text-slate-800'
              : 'bg-slate-900 border-slate-800 text-blue-400'
          }`}>
            <ShieldCheck className="w-7 h-7" />
          </div>

          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-lg sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                Serverless Security Verification Framework
              </h1>

              {/* Theme Toggle Button (Light / Dark) directly right of title */}
              <button
                id="btn-toggle-theme"
                type="button"
                onClick={toggleTheme}
                className={`glossy-btn flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-mono font-semibold transition-all border shadow-xs ${
                  theme === 'dark'
                    ? 'bg-slate-900 hover:bg-slate-800 text-slate-200 hover:text-white border-slate-800 hover:border-slate-700'
                    : 'bg-white hover:bg-slate-100 text-slate-800 hover:text-slate-950 border-slate-300 hover:border-slate-400'
                }`}
                title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
                aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
              >
                {theme === 'dark' ? (
                  <>
                    <Sun className="w-3.5 h-3.5 text-amber-400" />
                    <span className="font-sans font-medium text-[11px]">Light</span>
                  </>
                ) : (
                  <>
                    <Moon className="w-3.5 h-3.5 text-indigo-600" />
                    <span className="font-sans font-medium text-[11px]">Dark</span>
                  </>
                )}
              </button>

              <span className="text-[10px] uppercase font-mono px-2.5 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700 font-semibold tracking-wider">
                Zero Trust v2.4
              </span>

              {isEmergencyLockdownActive && (
                <span className="text-[10px] uppercase font-mono px-2.5 py-0.5 rounded-md bg-rose-600 text-white border border-rose-500 font-bold tracking-wider animate-pulse">
                  🚨 EMERGENCY LOCKDOWN
                </span>
              )}
            </div>

            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Autonomous Cloudflare Edge Policy Enforcement, Markov Sequence Validation &amp; Real-time Audit Ledger
            </p>
          </div>
        </div>

        {/* Global Toolbar Controls */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Active Workspace Status Badge - Themed to Active Section */}
          <div className={`hidden md:flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-mono ${
            isLight
              ? `${sectionMeta.tagBadgeLight} bg-white shadow-xs`
              : `${sectionMeta.tagBadgeDark} bg-slate-900/90`
          }`}>
            <span className="text-[10px] uppercase font-bold tracking-wider opacity-70">
              Sec {sectionMeta.sectionNumber}:
            </span>
            <span className="font-bold">{sectionMeta.tabName}</span>
          </div>

          {/* Active Session / IAM Trigger */}
          <button
            id="btn-open-auth-modal"
            onClick={onOpenAuthModal}
            className={`glossy-btn flex items-center gap-2 px-3.5 py-2.5 rounded-xl text-xs font-mono font-semibold transition-all border shadow-xs ${
              currentSession
                ? isLight
                  ? 'bg-white hover:bg-slate-50 text-slate-900 border-slate-300'
                  : 'bg-slate-900/90 hover:bg-slate-800 text-white border-slate-700 hover:border-slate-600'
                : isLight
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-900 border-slate-300'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
            }`}
            title="Open Identity & Access Portal"
          >
            {currentSession ? (
              <>
                <UserCheck className={`w-4 h-4 ${isLight ? 'text-blue-600' : 'text-blue-400'}`} />
                <div className="flex items-center gap-1.5">
                  <span className={`${isLight ? 'text-slate-900 font-bold' : 'text-slate-200 font-medium'}`}>
                    {currentSession.user.username}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded-md font-mono font-bold bg-slate-800 text-slate-200 border border-slate-700">
                    {currentSession.user.role}
                  </span>
                </div>
              </>
            ) : (
              <>
                <Lock className="w-4 h-4 text-slate-400" />
                <span>Sign In / Identity</span>
              </>
            )}
          </button>

          {/* Cloud Blueprint Specs */}
          <button
            id="btn-open-cloud-guide"
            onClick={onOpenCloudGuide}
            className={`glossy-btn flex items-center gap-1.5 px-3 py-2.5 rounded-xl border text-xs font-mono font-medium transition-colors shadow-xs ${
              isLight
                ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
            title="Open Cloud Deployment Blueprint & Architecture Manual"
          >
            <Cloud className="w-3.5 h-3.5 text-blue-400" />
            <span className="hidden sm:inline">Cloud Blueprint</span>
          </button>

          {/* Schema & Rules */}
          <button
            id="btn-inspect-db"
            onClick={onOpenDbModal}
            className={`glossy-btn flex items-center gap-1.5 px-3 py-2.5 rounded-xl text-xs font-mono transition-colors border shadow-xs ${
              isLight
                ? 'bg-white hover:bg-slate-100 text-slate-700 hover:text-slate-900 border-slate-300'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border-slate-800 hover:border-slate-700'
            }`}
            title="Inspect Database Schema & Markov Rules Matrix"
          >
            <Database className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Schema Matrix</span>
          </button>

          {/* Pending Approval Badge Notification */}
          {currentRole === 'Admin' && pendingApprovalCount > 0 && (
            <button
              id="btn-header-pending-approvals"
              onClick={onOpenUserDatabase ? onOpenUserDatabase : () => onSelectTab('admin')}
              className={`glossy-btn flex items-center gap-1.5 px-3 py-2.5 rounded-xl border text-xs font-mono font-medium transition-colors shadow-xs animate-pulse ${
                isLight
                  ? 'bg-amber-100 hover:bg-amber-200 text-amber-900 border-amber-300'
                  : 'bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border-amber-500/40'
              }`}
              title={`${pendingApprovalCount} pending registration approvals awaiting SecOps clearance`}
            >
              <Clock className="w-3.5 h-3.5 text-amber-400" />
              <span>{pendingApprovalCount} Approval{pendingApprovalCount > 1 ? 's' : ''}</span>
            </button>
          )}

          {currentSession && onLogout && (
            <button
              id="btn-logout"
              onClick={onLogout}
              className={`glossy-btn flex items-center gap-1.5 px-3 py-2.5 rounded-xl text-xs font-mono transition-colors border shadow-xs ${
                isLight
                  ? 'bg-rose-50 hover:bg-rose-100 text-rose-700 hover:text-rose-900 border-rose-200'
                  : 'bg-rose-950/30 hover:bg-rose-900/50 text-rose-300 hover:text-white border-rose-800/60'
              }`}
              title="Terminate Active Zero-Trust Session"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Sign Out</span>
            </button>
          )}
        </div>
      </div>

      {/* ACTIVE ROLE CLEARANCE BANNER (ONLY ACTIVE ROLE DISPLAYED) */}
      {currentSession && (
        <div className={`glossy-panel p-3.5 rounded-2xl flex flex-wrap items-center justify-between gap-3 text-xs font-mono transition-all border ${
          isLight ? sectionMeta.bannerBorderLight : sectionMeta.bannerBorderDark
        } ${isLight ? sectionMeta.bannerBgLight : sectionMeta.bannerBgDark}`}>
          <div className="flex items-center gap-2.5 flex-wrap">
            <span className="text-[11px] text-slate-400 flex items-center gap-1.5 uppercase tracking-wider font-semibold">
              <Fingerprint className={`w-3.5 h-3.5 ${isLight ? sectionMeta.accentTextLight : sectionMeta.accentTextDark}`} />
              Active Role Clearance:
            </span>
            <span className={`px-2.5 py-1 rounded-lg text-xs font-bold border ${
              isLight
                ? 'bg-white text-slate-800 border-slate-300 shadow-xs'
                : 'bg-slate-900 text-slate-100 border-slate-700'
            }`}>
              {currentRole === 'Admin' ? 'ADMINISTRATOR (TIER 3: UNRESTRICTED GOVERNANCE)' :
               currentRole === 'Developer' ? 'DEVELOPER (TIER 2: WORKBENCH & INVOCATION)' :
               'GUEST (TIER 1: TELEMETRY ONLY)'}
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700 font-bold">
              MFA VERIFIED
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-[11px]">Active Workspace:</span>
            <span className={`font-bold px-3 py-1 rounded-lg border ${
              isLight ? sectionMeta.tagBadgeLight : sectionMeta.tagBadgeDark
            }`}>
              [{sectionMeta.sectionNumber}] {sectionMeta.tabName}
            </span>
            <button
              type="button"
              onClick={onOpenSidebar}
              className={`text-[11px] font-sans font-semibold hover:underline underline-offset-2 ml-1 flex items-center gap-1 cursor-pointer ${
                isLight ? sectionMeta.accentTextLight : sectionMeta.accentTextDark
              }`}
            >
              <Menu className="w-3 h-3" />
              <span>Menu →</span>
            </button>
          </div>
        </div>
      )}
    </header>
  );
};
