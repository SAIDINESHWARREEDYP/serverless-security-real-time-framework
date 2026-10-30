import React, { useState } from 'react';
import {
  ShieldAlert,
  Shield,
  Bot,
  BarChart3,
  Users,
  Cpu,
  FileText,
  Code,
  UserCheck,
  LayoutGrid,
  X,
  Zap,
  Cloud,
  Database,
  Lock,
  ChevronRight,
  LogOut,
  AlertTriangle,
  FileDown,
  Search
} from 'lucide-react';
import { FeatureTabId } from './Header.tsx';
import { AuthSession } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';
import { SECTIONS_CONFIG, SectionMeta } from '../utils/sectionThemes.ts';

interface SidebarNavigationProps {
  isOpen: boolean;
  onClose: () => void;
  activeTab: FeatureTabId;
  onSelectTab: (tab: FeatureTabId) => void;
  currentSession: AuthSession | null;
  logsCount?: number;
  usersCount?: number;
  blockedCount?: number;
  pendingApprovalCount?: number;
  onOpenCloudGuide: () => void;
  onOpenDbModal: () => void;
  onOpenAuthModal: () => void;
  onOpenSecurityReport?: () => void;
  onLogout?: () => void;
  onRunCredentialStuffing?: () => void;
  onRunLateralMovementDrill?: () => void;
  onToggleEmergencyLockdown?: () => void;
  isEmergencyLockdownActive?: boolean;
}

export const SidebarNavigation: React.FC<SidebarNavigationProps> = ({
  isOpen,
  onClose,
  activeTab,
  onSelectTab,
  currentSession,
  logsCount = 0,
  usersCount = 0,
  blockedCount = 0,
  pendingApprovalCount = 0,
  onOpenCloudGuide,
  onOpenDbModal,
  onOpenAuthModal,
  onOpenSecurityReport,
  onLogout,
  onRunCredentialStuffing,
  onRunLateralMovementDrill,
  onToggleEmergencyLockdown,
  isEmergencyLockdownActive = false
}) => {
  const { isLight } = useTheme();
  const [filterQuery, setFilterQuery] = useState('');
  const currentRole = currentSession?.user.role || 'Guest';

  // Navigation items grouped by 4 disciplined sections with dedicated section colors
  const navSections = [
    {
      meta: SECTIONS_CONFIG.operations,
      items: [
        {
          id: 'admin' as FeatureTabId,
          label: 'SecOps Command Center',
          subtitle: 'System health, emergency controls & access clearances',
          icon: ShieldAlert,
          badge: 'Executive',
          tier: 'Tier 3 Admin',
          allowedRoles: ['Admin']
        },
        {
          id: 'interceptor' as FeatureTabId,
          label: 'Runtime Interceptor',
          subtitle: 'Live traffic simulation & packet policy verification',
          icon: Shield,
          badge: 'Live Sim',
          tier: 'Tier 3 Admin',
          allowedRoles: ['Admin']
        },
        {
          id: 'ai-threats' as FeatureTabId,
          label: 'AI Threat Sentinel',
          subtitle: 'Autonomous anomaly detection & Markov drift neural analysis',
          icon: Bot,
          badge: 'Autonomous',
          tier: 'Tier 2+ Dev',
          allowedRoles: ['Admin', 'Developer']
        }
      ]
    },
    {
      meta: SECTIONS_CONFIG.telemetry,
      items: [
        {
          id: 'health' as FeatureTabId,
          label: 'Threat Intelligence',
          subtitle: 'Multi-vector threat distribution & Markov metrics',
          icon: BarChart3,
          badge: blockedCount > 0 ? `${blockedCount} Blocked` : 'Nominal',
          tier: 'Tier 3 Admin',
          allowedRoles: ['Admin']
        },
        {
          id: 'audit' as FeatureTabId,
          label: 'Compliance Audit Ledger',
          subtitle: 'Immutable real-time zero-trust event stream',
          icon: FileText,
          badge: `${logsCount} Events`,
          tier: 'Public / All',
          allowedRoles: ['Admin', 'Developer', 'Guest']
        }
      ]
    },
    {
      meta: SECTIONS_CONFIG.policies,
      items: [
        {
          id: 'iam' as FeatureTabId,
          label: 'Identity & Governance',
          subtitle: 'Principals roster, role assignments & dynamic IAM onboarding',
          icon: Users,
          badge: `${usersCount} Principals`,
          tier: 'Tier 3 Admin',
          allowedRoles: ['Admin']
        },
        {
          id: 'architecture' as FeatureTabId,
          label: 'Policy Architecture & Blueprint',
          subtitle: 'Markov transition state machine & D1 SQL schema rules (SecOps Admin Only)',
          icon: Cpu,
          badge: 'Admin Only',
          tier: 'Tier 3 Admin',
          allowedRoles: ['Admin']
        }
      ]
    },
    {
      meta: SECTIONS_CONFIG.workbenches,
      items: [
        {
          id: 'developer' as FeatureTabId,
          label: 'Developer Console',
          subtitle: 'Cloud & edge mesh function testbed & payload sandbox',
          icon: Code,
          badge: 'Tier 2 Mesh',
          tier: 'Tier 2+ Dev',
          allowedRoles: ['Developer', 'Admin']
        },
        {
          id: 'guest' as FeatureTabId,
          label: 'Access Gateway',
          subtitle: 'Public read-only portal & guest sandbox experience',
          icon: UserCheck,
          badge: 'Public Tier 1',
          tier: 'Public / All',
          allowedRoles: ['Guest', 'Admin', 'Developer']
        },
        {
          id: 'overview' as FeatureTabId,
          label: 'Consolidated Matrix',
          subtitle: 'Executive synthesis & enterprise telemetry overview',
          icon: LayoutGrid,
          badge: 'Synthesis',
          tier: 'Tier 3 Admin',
          allowedRoles: ['Admin']
        }
      ]
    }
  ];

  if (!isOpen || !currentSession) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex">
      {/* Backdrop with glossy blur */}
      <div
        className="fixed inset-0 bg-slate-950/75 backdrop-blur-md transition-opacity duration-300 ease-out animate-fade-in"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Glossy Slide-out Sidebar Panel */}
      <div
        className={`relative w-full max-w-md sm:max-w-lg glossy-sidebar h-full flex flex-col z-10 transition-transform duration-300 ease-out shadow-2xl border-r ${
          isLight
            ? 'bg-white/95 border-slate-200 text-slate-800'
            : 'bg-[#080d1a]/95 border-slate-800/90 text-slate-100'
        }`}
        role="dialog"
        aria-modal="true"
        aria-label="Enterprise Navigation Menu"
      >
        {/* Drawer Header */}
        <div className={`p-5 border-b flex items-center justify-between ${
          isLight ? 'border-slate-200 bg-slate-50/70' : 'border-slate-800/80 bg-slate-900/40'
        }`}>
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse inline-block"></span>
              <h2 className="text-base font-bold tracking-tight">Navigation &amp; Workspaces</h2>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Disciplined 4-Section Enterprise Matrix
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className={`p-2 rounded-xl border transition-all ${
              isLight
                ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-200'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
            }`}
            aria-label="Close navigation menu"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Current Active Identity Strip */}
        <div className={`px-5 py-3 border-b text-xs ${
          isLight ? 'bg-slate-100/70 border-slate-200' : 'bg-slate-900/70 border-slate-800/80'
        }`}>
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-7 h-7 rounded-lg bg-blue-600 text-white font-bold text-xs flex items-center justify-center shrink-0 shadow-xs">
                {currentSession?.user.username?.[0]?.toUpperCase() || 'U'}
              </div>
              <div className="min-w-0">
                <div className="text-xs font-bold truncate">
                  {currentSession?.user.username || 'Unauthenticated'}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono flex items-center gap-1.5">
                  <span>Role:</span>
                  <span className="font-semibold text-slate-700 dark:text-slate-300">
                    {currentRole}
                  </span>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => {
                onClose();
                onOpenAuthModal();
              }}
              className={`text-xs font-mono font-medium px-3 py-1.5 rounded-xl border transition-all shrink-0 ${
                isLight
                  ? 'bg-white hover:bg-slate-100 text-slate-800 border-slate-300 shadow-xs'
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-200 border-slate-700 hover:border-slate-500'
              }`}
            >
              Switch Role
            </button>
          </div>
        </div>

        {/* Quick Filter Search */}
        <div className="px-5 pt-4 pb-2">
          <div className={`flex items-center gap-2.5 px-3 py-2 rounded-xl border text-xs font-mono transition-all ${
            isLight
              ? 'bg-slate-100 border-slate-200 text-slate-800 focus-within:border-blue-500'
              : 'bg-slate-900/80 border-slate-800 text-slate-200 focus-within:border-blue-500/70'
          }`}>
            <Search className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            <input
              type="text"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              placeholder="Filter workspace by name or role..."
              className="w-full bg-transparent border-none outline-none text-xs placeholder:text-slate-500"
            />
            {filterQuery && (
              <button
                type="button"
                onClick={() => setFilterQuery('')}
                className="text-slate-400 hover:text-white text-xs px-1"
              >
                ✕
              </button>
            )}
          </div>
        </div>

        {/* Scrollable Navigation Menu Sections with Section-Wise Color Identification */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-7 scrollbar-thin">
          {navSections.map(({ meta, items }) => {
            // Filter by search query if any
            const matchingItems = items.filter(item =>
              !filterQuery.trim() ||
              item.label.toLowerCase().includes(filterQuery.toLowerCase()) ||
              item.subtitle.toLowerCase().includes(filterQuery.toLowerCase()) ||
              item.tier.toLowerCase().includes(filterQuery.toLowerCase())
            );

            if (matchingItems.length === 0) return null;

            return (
              <div key={meta.id} className="space-y-3">
                {/* Clean Category Header with Dedicated Section Color Badge */}
                <div className="flex items-center justify-between border-b border-slate-800/40 pb-2">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                      isLight ? meta.tagBadgeLight : meta.tagBadgeDark
                    }`}>
                      {meta.sectionNumber}
                    </span>
                    <span className="text-xs font-mono uppercase tracking-wider text-slate-300 dark:text-slate-300 font-bold">
                      {meta.title}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">
                    {matchingItems.length} {matchingItems.length === 1 ? 'view' : 'views'}
                  </span>
                </div>

                {/* Menu Items with Consistent Section-Wise Styling */}
                <div className="space-y-3">
                  {matchingItems.map((item) => {
                    const Icon = item.icon;
                    const isActive = activeTab === item.id;
                    const isPermitted = item.allowedRoles.includes(currentRole);

                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => {
                          onSelectTab(item.id);
                          onClose();
                        }}
                        className={`w-full group flex items-center justify-between p-3.5 sm:p-4 rounded-2xl transition-all duration-200 border text-left cursor-pointer ${
                          isActive
                            ? isLight
                              ? meta.activeItemLight
                              : meta.activeItemDark
                            : isLight
                            ? 'bg-white hover:bg-slate-50 text-slate-800 border-slate-200 hover:border-slate-300 shadow-xs hover:shadow-sm'
                            : 'bg-slate-900/40 hover:bg-slate-800/80 text-slate-200 border-slate-800/80 hover:border-slate-700 shadow-xs hover:shadow-sm'
                        }`}
                      >
                        <div className="flex items-center gap-3.5 min-w-0">
                          {/* Section-Themed Icon Container */}
                          <div className={`p-2.5 rounded-xl transition-transform group-hover:scale-105 shrink-0 border ${
                            isActive
                              ? 'bg-white/20 text-white border-white/30 shadow-xs'
                              : isLight
                              ? meta.iconBoxLight
                              : meta.iconBoxDark
                          }`}>
                            <Icon className="w-5 h-5" />
                          </div>

                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-bold tracking-tight truncate">
                                {item.label}
                              </span>
                              {isActive && (
                                <span className="w-2 h-2 rounded-full bg-white animate-pulse"></span>
                              )}
                            </div>
                            <p className={`text-xs mt-0.5 line-clamp-1 ${
                              isActive
                                ? 'text-white/80 font-medium'
                                : 'text-slate-500 dark:text-slate-400'
                            }`}>
                              {item.subtitle}
                            </p>
                          </div>
                        </div>

                        {/* Right Section-Themed Badges */}
                        <div className="flex items-center gap-2.5 shrink-0 ml-3">
                          <div className="flex flex-col items-end gap-1">
                            <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-md border font-semibold ${
                              isActive
                                ? 'bg-white/20 text-white border-white/30'
                                : isLight
                                ? meta.tagBadgeLight
                                : meta.tagBadgeDark
                            }`}>
                              {item.badge}
                            </span>
                            {!isPermitted && (
                              <span className="text-[9px] font-mono text-slate-400 flex items-center gap-1">
                                <Lock className="w-2.5 h-2.5" />
                                {item.tier}
                              </span>
                            )}
                          </div>
                          <ChevronRight className={`w-4 h-4 transition-transform group-hover:translate-x-1 ${
                            isActive ? 'text-white' : 'text-slate-500 opacity-60 group-hover:opacity-100'
                          }`} />
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}

          {/* Incident Simulation Drills (Admin Only) */}
          {currentRole === 'Admin' && (
            <div className="space-y-3 pt-3 border-t border-slate-800/80">
              <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold flex items-center gap-2">
                <Zap className="w-4 h-4 text-blue-400" />
                <span>Incident Simulation Drills</span>
              </div>

              <div className="grid grid-cols-1 gap-2.5">
                {onRunCredentialStuffing && (
                  <button
                    type="button"
                    onClick={() => {
                      onRunCredentialStuffing();
                      onClose();
                    }}
                    className={`flex items-center justify-between p-3 rounded-xl border text-xs font-medium transition-all ${
                      isLight
                        ? 'bg-slate-50 hover:bg-slate-100 text-slate-800 border-slate-200'
                        : 'bg-slate-900/60 hover:bg-slate-800 text-slate-200 border-slate-800'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <AlertTriangle className="w-4 h-4 text-amber-500" />
                      <span className="font-semibold">Credential Spray Attack Wave</span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      Trigger
                    </span>
                  </button>
                )}

                {onRunLateralMovementDrill && (
                  <button
                    type="button"
                    onClick={() => {
                      onRunLateralMovementDrill();
                      onClose();
                    }}
                    className={`flex items-center justify-between p-3 rounded-xl border text-xs font-medium transition-all ${
                      isLight
                        ? 'bg-slate-50 hover:bg-slate-100 text-slate-800 border-slate-200'
                        : 'bg-slate-900/60 hover:bg-slate-800 text-slate-200 border-slate-800'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Cpu className="w-4 h-4 text-indigo-400" />
                      <span className="font-semibold">Lateral Markov Drift Drill</span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      Trigger
                    </span>
                  </button>
                )}

                {onToggleEmergencyLockdown && (
                  <button
                    type="button"
                    onClick={() => {
                      onToggleEmergencyLockdown();
                      onClose();
                    }}
                    className={`flex items-center justify-between p-3 rounded-xl border text-xs font-bold transition-all ${
                      isEmergencyLockdownActive
                        ? 'bg-rose-600 hover:bg-rose-500 text-white border-rose-400 shadow-md shadow-rose-600/30'
                        : isLight
                        ? 'bg-rose-50 hover:bg-rose-100 text-rose-800 border-rose-200'
                        : 'bg-rose-950/20 hover:bg-rose-900/40 text-rose-300 border-rose-900/40'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <ShieldAlert className="w-4 h-4 text-rose-500" />
                      <span>{isEmergencyLockdownActive ? 'Emergency Lockdown ACTIVE' : 'Engage Perimeter Lockdown'}</span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">
                      {isEmergencyLockdownActive ? 'ENGAGED' : '25% Limit'}
                    </span>
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Architecture Specifications & Compliance Downloads */}
          <div className="space-y-3 pt-3 border-t border-slate-800/80">
            <div className="text-xs font-mono uppercase tracking-wider text-slate-400 dark:text-slate-500 font-bold">
              Engineering Blueprints &amp; Export
            </div>

            {/* Admin-Only Cloud Blueprint & Schema Inspection Access */}
            {currentRole === 'Admin' && (
              <div className="grid grid-cols-2 gap-2.5">
                <button
                  type="button"
                  onClick={() => {
                    onClose();
                    onOpenCloudGuide();
                  }}
                  className={`p-3 rounded-xl border text-xs font-mono flex items-center gap-2 transition-all ${
                    isLight
                      ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-200 shadow-xs'
                      : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <Cloud className="w-4 h-4 text-blue-400" />
                  <span className="truncate">Cloud Blueprint</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    onClose();
                    onOpenDbModal();
                  }}
                  className={`p-3 rounded-xl border text-xs font-mono flex items-center gap-2 transition-all ${
                    isLight
                      ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-200 shadow-xs'
                      : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <Database className="w-4 h-4 text-slate-400" />
                  <span className="truncate">Schema Matrix</span>
                </button>
              </div>
            )}

            {onOpenSecurityReport && (
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onOpenSecurityReport();
                }}
                className={`w-full p-3 rounded-xl border text-xs font-mono flex items-center justify-between transition-all ${
                  isLight
                    ? 'bg-slate-50 hover:bg-slate-100 text-slate-800 border-slate-200 shadow-xs'
                    : 'bg-slate-900 hover:bg-slate-800 text-slate-200 border-slate-800'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <FileDown className="w-4 h-4 text-emerald-400" />
                  <span className="font-medium">Download Compliance Audit Report</span>
                </div>
                <span className="text-[10px] font-mono text-slate-400 font-bold">PDF / JSON</span>
              </button>
            )}
          </div>
        </div>

        {/* Sidebar Footer with Session Sign Out */}
        {currentSession && onLogout && (
          <div className={`p-4 sm:p-5 border-t ${
            isLight ? 'border-slate-200 bg-slate-50' : 'border-slate-800/90 bg-[#060a14]'
          }`}>
            <button
              type="button"
              onClick={() => {
                onClose();
                onLogout();
              }}
              className={`w-full py-3 px-4 rounded-xl text-xs font-mono font-semibold transition-all border flex items-center justify-center gap-2.5 ${
                isLight
                  ? 'bg-rose-50 hover:bg-rose-100 text-rose-700 border-rose-200 shadow-xs'
                  : 'bg-rose-950/30 hover:bg-rose-900/50 text-rose-300 border-rose-800/50'
              }`}
            >
              <LogOut className="w-4 h-4" />
              <span>Terminate Session (Sign Out)</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
