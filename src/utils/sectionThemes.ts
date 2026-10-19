import { FeatureTabId } from '../components/Header.tsx';

export type SectionColorKey = 'blue' | 'emerald' | 'indigo' | 'cyan';

export interface SectionMeta {
  id: 'operations' | 'telemetry' | 'policies' | 'workbenches';
  sectionNumber: '01' | '02' | '03' | '04';
  title: string;
  description: string;
  colorKey: SectionColorKey;
  // Classes
  tagBadgeLight: string;
  tagBadgeDark: string;
  activeItemLight: string;
  activeItemDark: string;
  iconBoxLight: string;
  iconBoxDark: string;
  accentTextLight: string;
  accentTextDark: string;
  bannerBorderLight: string;
  bannerBorderDark: string;
  bannerBgLight: string;
  bannerBgDark: string;
}

export const SECTIONS_CONFIG: Record<string, SectionMeta> = {
  operations: {
    id: 'operations',
    sectionNumber: '01',
    title: 'Core Governance & Operations',
    description: 'Central incident response, live interceptors & autonomous sentinel',
    colorKey: 'blue',
    tagBadgeLight: 'bg-blue-50 text-blue-700 border-blue-200',
    tagBadgeDark: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
    activeItemLight: 'bg-blue-600 text-white border-blue-500 shadow-md shadow-blue-500/25 ring-2 ring-blue-500/20',
    activeItemDark: 'bg-gradient-to-r from-blue-600/30 via-blue-500/20 to-blue-700/25 text-white border-blue-400/80 shadow-lg shadow-blue-500/15 ring-1 ring-blue-400/40',
    iconBoxLight: 'bg-blue-50 text-blue-600 border-blue-200',
    iconBoxDark: 'bg-blue-950/60 text-blue-400 border-blue-800/60',
    accentTextLight: 'text-blue-700',
    accentTextDark: 'text-blue-400',
    bannerBorderLight: 'border-blue-200',
    bannerBorderDark: 'border-blue-500/30',
    bannerBgLight: 'bg-blue-50/50',
    bannerBgDark: 'bg-blue-950/20'
  },
  telemetry: {
    id: 'telemetry',
    sectionNumber: '02',
    title: 'Security Telemetry & Compliance',
    description: 'Multi-vector telemetry, risk distribution & immutable audit ledger',
    colorKey: 'emerald',
    tagBadgeLight: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    tagBadgeDark: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    activeItemLight: 'bg-emerald-600 text-white border-emerald-500 shadow-md shadow-emerald-500/25 ring-2 ring-emerald-500/20',
    activeItemDark: 'bg-gradient-to-r from-emerald-600/30 via-emerald-500/20 to-emerald-700/25 text-white border-emerald-400/80 shadow-lg shadow-emerald-500/15 ring-1 ring-emerald-400/40',
    iconBoxLight: 'bg-emerald-50 text-emerald-600 border-emerald-200',
    iconBoxDark: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60',
    accentTextLight: 'text-emerald-700',
    accentTextDark: 'text-emerald-400',
    bannerBorderLight: 'border-emerald-200',
    bannerBorderDark: 'border-emerald-500/30',
    bannerBgLight: 'bg-emerald-50/50',
    bannerBgDark: 'bg-emerald-950/20'
  },
  policies: {
    id: 'policies',
    sectionNumber: '03',
    title: 'Identity & Access Policies',
    description: 'Principals roster, dynamic IAM onboarding & formal Markov state machine',
    colorKey: 'indigo',
    tagBadgeLight: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    tagBadgeDark: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30',
    activeItemLight: 'bg-indigo-600 text-white border-indigo-500 shadow-md shadow-indigo-500/25 ring-2 ring-indigo-500/20',
    activeItemDark: 'bg-gradient-to-r from-indigo-600/30 via-indigo-500/20 to-indigo-700/25 text-white border-indigo-400/80 shadow-lg shadow-indigo-500/15 ring-1 ring-indigo-400/40',
    iconBoxLight: 'bg-indigo-50 text-indigo-600 border-indigo-200',
    iconBoxDark: 'bg-indigo-950/60 text-indigo-400 border-indigo-800/60',
    accentTextLight: 'text-indigo-700',
    accentTextDark: 'text-indigo-400',
    bannerBorderLight: 'border-indigo-200',
    bannerBorderDark: 'border-indigo-500/30',
    bannerBgLight: 'bg-indigo-50/50',
    bannerBgDark: 'bg-indigo-950/20'
  },
  workbenches: {
    id: 'workbenches',
    sectionNumber: '04',
    title: 'Role Workbenches & Synthesis',
    description: 'Developer sandbox testbed, public access portal & executive matrix',
    colorKey: 'cyan',
    tagBadgeLight: 'bg-cyan-50 text-cyan-700 border-cyan-200',
    tagBadgeDark: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
    activeItemLight: 'bg-cyan-600 text-white border-cyan-500 shadow-md shadow-cyan-500/25 ring-2 ring-cyan-500/20',
    activeItemDark: 'bg-gradient-to-r from-cyan-600/30 via-cyan-500/20 to-cyan-700/25 text-white border-cyan-400/80 shadow-lg shadow-cyan-500/15 ring-1 ring-cyan-400/40',
    iconBoxLight: 'bg-cyan-50 text-cyan-600 border-cyan-200',
    iconBoxDark: 'bg-cyan-950/60 text-cyan-400 border-cyan-800/60',
    accentTextLight: 'text-cyan-700',
    accentTextDark: 'text-cyan-400',
    bannerBorderLight: 'border-cyan-200',
    bannerBorderDark: 'border-cyan-500/30',
    bannerBgLight: 'bg-cyan-50/50',
    bannerBgDark: 'bg-cyan-950/20'
  }
};

export const TAB_TO_SECTION_MAP: Record<FeatureTabId, {
  sectionId: 'operations' | 'telemetry' | 'policies' | 'workbenches';
  tabName: string;
  tabRoleTier: string;
}> = {
  admin: {
    sectionId: 'operations',
    tabName: 'SecOps Command Center',
    tabRoleTier: 'Tier 3 Admin'
  },
  interceptor: {
    sectionId: 'operations',
    tabName: 'Runtime Interceptor',
    tabRoleTier: 'Tier 3 Admin'
  },
  'ai-threats': {
    sectionId: 'operations',
    tabName: 'AI Threat Sentinel',
    tabRoleTier: 'Tier 2+ Dev'
  },
  health: {
    sectionId: 'telemetry',
    tabName: 'Threat Intelligence',
    tabRoleTier: 'Tier 3 Admin'
  },
  audit: {
    sectionId: 'telemetry',
    tabName: 'Compliance Audit Ledger',
    tabRoleTier: 'Public / All'
  },
  iam: {
    sectionId: 'policies',
    tabName: 'Identity & Governance',
    tabRoleTier: 'Tier 3 Admin'
  },
  architecture: {
    sectionId: 'policies',
    tabName: 'Policy Architecture',
    tabRoleTier: 'Tier 2+ Dev'
  },
  developer: {
    sectionId: 'workbenches',
    tabName: 'Developer Console',
    tabRoleTier: 'Tier 2+ Dev'
  },
  guest: {
    sectionId: 'workbenches',
    tabName: 'Access Gateway',
    tabRoleTier: 'Public / All'
  },
  overview: {
    sectionId: 'workbenches',
    tabName: 'Consolidated Matrix',
    tabRoleTier: 'Tier 3 Admin'
  }
};

export function getSectionMetaForTab(tab: FeatureTabId): SectionMeta & { tabName: string; tabRoleTier: string } {
  const mapping = TAB_TO_SECTION_MAP[tab] || TAB_TO_SECTION_MAP.admin;
  const section = SECTIONS_CONFIG[mapping.sectionId];
  return {
    ...section,
    tabName: mapping.tabName,
    tabRoleTier: mapping.tabRoleTier
  };
}
