import React, { useMemo, useState, useEffect } from 'react';
import {
  Grid,
  ShieldAlert,
  ShieldCheck,
  Search,
  X,
  Download,
  Check,
  Clock,
  Layers,
  Crosshair,
  Activity,
  Lock,
  Radio,
  KeyRound,
  Archive,
  ChevronDown,
  ChevronUp,
  AlertTriangle
} from 'lucide-react';
import {
  SecurityAuditLog,
  RealtimeTelemetrySnapshot,
  AuditChainAnchorStatus,
  AuditChainVerificationResult
} from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';
import { getAuthRequestHeaders } from '../utils/authTokenStore.ts';

function isGovernanceAdmin(role?: string): boolean {
  const normalized = (role || '').trim();
  return (
    normalized === 'Admin' ||
    normalized === 'Super Administrator' ||
    normalized === 'Security Administrator'
  );
}

export type HeatmapAxisMode = 'temporal' | 'vector';
export type HeatmapIntensityBasis = 'composite' | 'blocked' | 'volume';
export type HeatmapTrafficFilter = 'ALL' | 'BLOCKED' | 'HIGH_RISK';

export type ThreatVectorBucket =
  | 'Cloud SSRF'
  | 'Injection / RCE'
  | 'RBAC Breach'
  | 'Markov Drift'
  | 'Rate Burst'
  | 'Lockdown / Auth'
  | 'Nominal Baseline';

export const THREAT_VECTOR_COLUMNS: ThreatVectorBucket[] = [
  'Cloud SSRF',
  'Injection / RCE',
  'RBAC Breach',
  'Markov Drift',
  'Rate Burst',
  'Lockdown / Auth',
  'Nominal Baseline'
];

export function normalizeFunctionName(rawFn: string): string {
  const cleaned = (rawFn || 'unknown')
    .trim()
    .replace(/^https?:\/\/[^/]+/, '')
    .replace(/^\/api\/v1\//, '')
    .replace(/^\/api\//, '')
    .replace(/^\//, '');
  return cleaned || 'root';
}

export function classifyThreatVector(log: SecurityAuditLog): ThreatVectorBucket {
  const ev = (log.event_type || '').toUpperCase();
  const reason = (log.reason || '').toLowerCase();

  if (
    ev.includes('SSRF') ||
    reason.includes('169.254.169.254') ||
    reason.includes('metadata') ||
    reason.includes('ssrf')
  ) {
    return 'Cloud SSRF';
  }
  if (
    ev.includes('COMMAND') ||
    ev.includes('SQL') ||
    ev.includes('PROMPT') ||
    ev.includes('DESERIALIZATION') ||
    ev.includes('CREDENTIAL') ||
    reason.includes('injection') ||
    reason.includes('shellcode') ||
    reason.includes('deserialization') ||
    reason.includes('sql') ||
    reason.includes('prompt')
  ) {
    return 'Injection / RCE';
  }
  if (
    ev.includes('RBAC') ||
    ev.includes('PRIVILEGE') ||
    ev.includes('UNAUTHORIZED') ||
    reason.includes('rbac') ||
    reason.includes('permission') ||
    reason.includes('unauthorized role')
  ) {
    return 'RBAC Breach';
  }
  if (
    ev.includes('SEQUENCE') ||
    ev.includes('MARKOV') ||
    reason.includes('markov') ||
    reason.includes('sequence') ||
    reason.includes('abnormal invocation order')
  ) {
    return 'Markov Drift';
  }
  if (
    ev.includes('RATE') ||
    reason.includes('rate limit') ||
    reason.includes('burst') ||
    reason.includes('abnormal_request_rate')
  ) {
    return 'Rate Burst';
  }
  if (
    log.status === 'BLOCKED' ||
    ev.includes('LOCKDOWN') ||
    ev.includes('FAIL_CLOSED') ||
    ev.includes('AUTH') ||
    reason.includes('lockdown') ||
    reason.includes('revoked')
  ) {
    return 'Lockdown / Auth';
  }
  return 'Nominal Baseline';
}

export interface HeatmapCellData {
  xIndex: number;
  yIndex: number;
  columnLabel: string;
  functionName: string;
  totalHits: number;
  blockedHits: number;
  allowedHits: number;
  maxRisk: number;
  avgRisk: number;
  avgLatencyMs: number;
  intensity: number; // 0..1 calibrated score
  severityLabel: 'Empty' | 'Nominal' | 'Guarded' | 'Elevated' | 'Critical';
  topPrincipals: Array<{ username: string; count: number }>;
  containsLatestLive: boolean;
  logs: SecurityAuditLog[];
}

export interface FunctionAttackSummary {
  functionName: string;
  totalHits: number;
  blockedHits: number;
  allowedHits: number;
  peakRisk: number;
  avgRisk: number;
  blockRatePct: number;
  attackSharePct: number;
  primaryVector: ThreatVectorBucket;
  lastSeenTimestamp: string;
}

export interface HeatmapModel {
  columns: Array<{ label: string; subLabel: string }>;
  rows: FunctionAttackSummary[];
  cells: HeatmapCellData[][];
  maxCellHits: number;
  maxBlockedHits: number;
  totalEvaluatedLogs: number;
  totalBlockedLogs: number;
  hottestCell: HeatmapCellData | null;
}

export function buildHeatmapModel(params: {
  logs: SecurityAuditLog[];
  axisMode: HeatmapAxisMode;
  intensityBasis: HeatmapIntensityBasis;
  trafficFilter: HeatmapTrafficFilter;
  functionQuery: string;
  maxThreshold: number;
  maxRows?: number;
  temporalBucketCount?: number;
}): HeatmapModel {
  const {
    logs,
    axisMode,
    intensityBasis,
    trafficFilter,
    functionQuery,
    maxThreshold,
    maxRows = 9,
    temporalBucketCount = 12
  } = params;

  const q = functionQuery.trim().toLowerCase();
  const filteredLogs = logs.filter((log) => {
    if (trafficFilter === 'BLOCKED' && log.status !== 'BLOCKED') return false;
    if (trafficFilter === 'HIGH_RISK' && log.calculated_risk < maxThreshold) return false;
    if (q) {
      const fnName = normalizeFunctionName(log.requested_function).toLowerCase();
      const user = (log.username || '').toLowerCase();
      if (!fnName.includes(q) && !user.includes(q)) return false;
    }
    return true;
  });

  if (filteredLogs.length === 0) {
    return {
      columns:
        axisMode === 'vector'
          ? THREAT_VECTOR_COLUMNS.map((v) => ({ label: v, subLabel: 'Vector' }))
          : Array.from({ length: temporalBucketCount }).map((_, idx) => ({
              label: `T-${temporalBucketCount - idx}`,
              subLabel: 'Idle'
            })),
      rows: [],
      cells: [],
      maxCellHits: 0,
      maxBlockedHits: 0,
      totalEvaluatedLogs: 0,
      totalBlockedLogs: 0,
      hottestCell: null
    };
  }

  // Chronological oldest -> newest for temporal coordinate mapping
  const chronological = [...filteredLogs].sort((a, b) => a.id - b.id);
  const latestLogId = chronological[chronological.length - 1]?.id;
  const totalBlockedLogs = chronological.filter((l) => l.status === 'BLOCKED').length;

  // Aggregate per-function stats to rank most frequently attacked functions on Y-axis
  const fnAggMap = new Map<
    string,
    {
      totalHits: number;
      blockedHits: number;
      allowedHits: number;
      peakRisk: number;
      sumRisk: number;
      vectorCounts: Map<ThreatVectorBucket, number>;
      lastSeenTimestamp: string;
    }
  >();

  for (const log of chronological) {
    const fnName = normalizeFunctionName(log.requested_function);
    let entry = fnAggMap.get(fnName);
    if (!entry) {
      entry = {
        totalHits: 0,
        blockedHits: 0,
        allowedHits: 0,
        peakRisk: 0,
        sumRisk: 0,
        vectorCounts: new Map(),
        lastSeenTimestamp: log.timestamp
      };
      fnAggMap.set(fnName, entry);
    }
    entry.totalHits += 1;
    if (log.status === 'BLOCKED') entry.blockedHits += 1;
    else entry.allowedHits += 1;
    entry.peakRisk = Math.max(entry.peakRisk, log.calculated_risk);
    entry.sumRisk += log.calculated_risk;
    entry.lastSeenTimestamp = log.timestamp;
    const vec = classifyThreatVector(log);
    entry.vectorCounts.set(vec, (entry.vectorCounts.get(vec) || 0) + 1);
  }

  const rankedFunctions: FunctionAttackSummary[] = Array.from(fnAggMap.entries())
    .map(([functionName, agg]) => {
      let primaryVector: ThreatVectorBucket = 'Nominal Baseline';
      let topVecScore = -1;
      for (const [vec, count] of agg.vectorCounts.entries()) {
        const weighted = vec === 'Nominal Baseline' ? count * 0.25 : count;
        if (weighted > topVecScore) {
          topVecScore = weighted;
          primaryVector = vec;
        }
      }
      return {
        functionName,
        totalHits: agg.totalHits,
        blockedHits: agg.blockedHits,
        allowedHits: agg.allowedHits,
        peakRisk: agg.peakRisk,
        avgRisk: Math.round(agg.sumRisk / agg.totalHits),
        blockRatePct: Math.round((agg.blockedHits / agg.totalHits) * 100),
        attackSharePct:
          totalBlockedLogs > 0
            ? Math.round((agg.blockedHits / totalBlockedLogs) * 100)
            : Math.round((agg.totalHits / chronological.length) * 100),
        primaryVector,
        lastSeenTimestamp: agg.lastSeenTimestamp
      };
    })
    .sort((a, b) => {
      if (b.blockedHits !== a.blockedHits) return b.blockedHits - a.blockedHits;
      if (b.peakRisk !== a.peakRisk) return b.peakRisk - a.peakRisk;
      return b.totalHits - a.totalHits;
    })
    .slice(0, maxRows);

  const rowIndexByFn = new Map<string, number>();
  rankedFunctions.forEach((r, idx) => rowIndexByFn.set(r.functionName, idx));

  // Build X-axis columns and map each log to (x, y)
  let columns: Array<{ label: string; subLabel: string }> = [];
  const rawGridLogs: SecurityAuditLog[][][] = [];

  if (axisMode === 'vector') {
    columns = THREAT_VECTOR_COLUMNS.map((vec) => ({
      label: vec,
      subLabel: vec === 'Nominal Baseline' ? 'Clean' : 'Attack'
    }));
  } else {
    const colCount = Math.min(temporalBucketCount, Math.max(4, chronological.length));
    const bucketSize = Math.ceil(chronological.length / colCount);
    const actualColCount = Math.ceil(chronological.length / bucketSize);

    for (let x = 0; x < actualColCount; x++) {
      const slice = chronological.slice(x * bucketSize, (x + 1) * bucketSize);
      const last = slice[slice.length - 1];
      const dt = new Date(last.timestamp);
      const label = isNaN(dt.getTime())
        ? `#${slice[0].id}-${last.id}`
        : dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      columns.push({
        label,
        subLabel: `${slice.length} ev`
      });
    }
  }

  for (let y = 0; y < rankedFunctions.length; y++) {
    rawGridLogs[y] = Array.from({ length: columns.length }, () => []);
  }

  if (axisMode === 'vector') {
    for (const log of chronological) {
      const fnName = normalizeFunctionName(log.requested_function);
      const y = rowIndexByFn.get(fnName);
      if (y === undefined) continue;
      const vec = classifyThreatVector(log);
      const x = THREAT_VECTOR_COLUMNS.indexOf(vec);
      if (x >= 0) rawGridLogs[y][x].push(log);
    }
  } else {
    const colCount = columns.length;
    const bucketSize = Math.ceil(chronological.length / colCount);
    for (let idx = 0; idx < chronological.length; idx++) {
      const log = chronological[idx];
      const fnName = normalizeFunctionName(log.requested_function);
      const y = rowIndexByFn.get(fnName);
      if (y === undefined) continue;
      const x = Math.min(colCount - 1, Math.floor(idx / bucketSize));
      rawGridLogs[y][x].push(log);
    }
  }

  // First pass: find max hits & blocked hits across cells for intensity normalization
  let maxCellHits = 0;
  let maxBlockedHits = 0;
  for (let y = 0; y < rankedFunctions.length; y++) {
    for (let x = 0; x < columns.length; x++) {
      const cellLogs = rawGridLogs[y][x];
      if (cellLogs.length > maxCellHits) maxCellHits = cellLogs.length;
      const blk = cellLogs.filter((l) => l.status === 'BLOCKED').length;
      if (blk > maxBlockedHits) maxBlockedHits = blk;
    }
  }

  let hottestCell: HeatmapCellData | null = null;
  const cells: HeatmapCellData[][] = rawGridLogs.map((rowBuckets, yIndex) =>
    rowBuckets.map((cellLogs, xIndex) => {
      const functionName = rankedFunctions[yIndex].functionName;
      const columnLabel = columns[xIndex].label;
      if (cellLogs.length === 0) {
        return {
          xIndex,
          yIndex,
          columnLabel,
          functionName,
          totalHits: 0,
          blockedHits: 0,
          allowedHits: 0,
          maxRisk: 0,
          avgRisk: 0,
          avgLatencyMs: 0,
          intensity: 0,
          severityLabel: 'Empty',
          topPrincipals: [],
          containsLatestLive: false,
          logs: []
        };
      }

      const blockedHits = cellLogs.filter((l) => l.status === 'BLOCKED').length;
      const allowedHits = cellLogs.length - blockedHits;
      const maxRisk = Math.max(...cellLogs.map((l) => l.calculated_risk));
      const avgRisk = Math.round(
        cellLogs.reduce((acc, l) => acc + l.calculated_risk, 0) / cellLogs.length
      );
      const latencies = cellLogs
        .map((l) => l.verification_latency_ms)
        .filter((n): n is number => typeof n === 'number' && n > 0);
      const avgLatencyMs =
        latencies.length > 0
          ? Number((latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(3))
          : 0;

      const principalCounts = new Map<string, number>();
      for (const l of cellLogs) {
        principalCounts.set(l.username, (principalCounts.get(l.username) || 0) + 1);
      }
      const topPrincipals = Array.from(principalCounts.entries())
        .map(([username, count]) => ({ username, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 4);

      const normVol = maxCellHits > 0 ? cellLogs.length / maxCellHits : 0;
      const normBlocked = maxBlockedHits > 0 ? blockedHits / maxBlockedHits : 0;
      const normRisk = Math.min(1, maxRisk / 100);
      const blockedRatio = blockedHits / cellLogs.length;

      let intensity = 0;
      if (intensityBasis === 'blocked') {
        intensity = blockedHits === 0 ? Math.min(0.18, normRisk * 0.18) : Math.min(1, 0.35 + normBlocked * 0.45 + normRisk * 0.2);
      } else if (intensityBasis === 'volume') {
        intensity = Math.min(1, 0.15 + normVol * 0.7 + blockedRatio * 0.15);
      } else {
        // Composite Threat Intensity: blends peak risk, blocked density & invocation volume
        intensity = Math.min(1, normRisk * 0.48 + blockedRatio * 0.32 + normBlocked * 0.12 + normVol * 0.08);
      }

      const severityLabel: HeatmapCellData['severityLabel'] =
        intensity >= 0.72 || maxRisk >= maxThreshold
          ? 'Critical'
          : intensity >= 0.48 || maxRisk >= 50
          ? 'Elevated'
          : intensity >= 0.24 || maxRisk >= 25
          ? 'Guarded'
          : 'Nominal';

      const cell: HeatmapCellData = {
        xIndex,
        yIndex,
        columnLabel,
        functionName,
        totalHits: cellLogs.length,
        blockedHits,
        allowedHits,
        maxRisk,
        avgRisk,
        avgLatencyMs,
        intensity: Number(intensity.toFixed(3)),
        severityLabel,
        topPrincipals,
        containsLatestLive: cellLogs.some((l) => l.id === latestLogId),
        logs: [...cellLogs].reverse()
      };

      if (
        !hottestCell ||
        cell.intensity > hottestCell.intensity ||
        (cell.intensity === hottestCell.intensity && cell.blockedHits > hottestCell.blockedHits)
      ) {
        hottestCell = cell;
      }

      return cell;
    })
  );

  return {
    columns,
    rows: rankedFunctions,
    cells,
    maxCellHits,
    maxBlockedHits,
    totalEvaluatedLogs: chronological.length,
    totalBlockedLogs,
    hottestCell
  };
}

function getHeatmapCellVisuals(cell: HeatmapCellData, isLight: boolean, isSelected: boolean) {
  if (cell.totalHits === 0) {
    return {
      background: isLight ? 'rgba(241, 245, 249, 0.75)' : 'rgba(15, 23, 42, 0.55)',
      borderColor: isSelected
        ? '#0284c7'
        : isLight
        ? 'rgba(203, 213, 225, 0.7)'
        : 'rgba(30, 41, 59, 0.85)',
      textColor: isLight ? '#94a3b8' : '#475569',
      glowShadow: 'none'
    };
  }

  const intensity = Math.max(0.12, Math.min(1, cell.intensity));

  if (cell.severityLabel === 'Critical') {
    const alpha = isLight ? 0.18 + intensity * 0.28 : 0.24 + intensity * 0.44;
    return {
      background: `linear-gradient(145deg, rgba(244, 63, 94, ${alpha.toFixed(2)}), rgba(190, 18, 60, ${(alpha * 0.85).toFixed(2)}))`,
      borderColor: isSelected ? '#ffffff' : isLight ? 'rgba(225, 29, 72, 0.75)' : 'rgba(251, 113, 133, 0.72)',
      textColor: isLight ? '#881337' : '#ffe4e6',
      glowShadow: isSelected
        ? '0 0 0 2px rgba(244, 63, 94, 0.8), 0 8px 20px -4px rgba(244, 63, 94, 0.45)'
        : `0 4px 14px -3px rgba(244, 63, 94, ${(0.2 + intensity * 0.25).toFixed(2)})`
    };
  }

  if (cell.severityLabel === 'Elevated') {
    const alpha = isLight ? 0.16 + intensity * 0.22 : 0.2 + intensity * 0.36;
    return {
      background: `linear-gradient(145deg, rgba(245, 158, 11, ${alpha.toFixed(2)}), rgba(217, 119, 6, ${(alpha * 0.85).toFixed(2)}))`,
      borderColor: isSelected ? '#fbbf24' : isLight ? 'rgba(217, 119, 6, 0.65)' : 'rgba(251, 191, 36, 0.55)',
      textColor: isLight ? '#78350f' : '#fef3c7',
      glowShadow: isSelected ? '0 0 0 2px rgba(245, 158, 11, 0.75)' : 'none'
    };
  }

  if (cell.severityLabel === 'Guarded') {
    const alpha = isLight ? 0.14 + intensity * 0.2 : 0.18 + intensity * 0.32;
    return {
      background: `linear-gradient(145deg, rgba(14, 165, 233, ${alpha.toFixed(2)}), rgba(2, 132, 199, ${(alpha * 0.85).toFixed(2)}))`,
      borderColor: isSelected ? '#38bdf8' : isLight ? 'rgba(2, 132, 199, 0.55)' : 'rgba(56, 189, 248, 0.48)',
      textColor: isLight ? '#0c4a6e' : '#e0f2fe',
      glowShadow: isSelected ? '0 0 0 2px rgba(56, 189, 248, 0.75)' : 'none'
    };
  }

  // Nominal
  const alpha = isLight ? 0.12 + intensity * 0.18 : 0.14 + intensity * 0.26;
  return {
    background: `linear-gradient(145deg, rgba(16, 185, 129, ${alpha.toFixed(2)}), rgba(5, 150, 105, ${(alpha * 0.85).toFixed(2)}))`,
    borderColor: isSelected ? '#34d399' : isLight ? 'rgba(5, 150, 105, 0.45)' : 'rgba(52, 211, 153, 0.38)',
    textColor: isLight ? '#064e3b' : '#d1fae5',
    glowShadow: isSelected ? '0 0 0 2px rgba(16, 185, 129, 0.7)' : 'none'
  };
}

interface ThreatHeatmapProps {
  logs: SecurityAuditLog[];
  maxThreshold?: number;
  realtimeTelemetry?: RealtimeTelemetrySnapshot;
  userRole?: string;
  onLogsMutated?: () => void;
}

type ChainVerifyResult = AuditChainVerificationResult;

export const ThreatHeatmap: React.FC<ThreatHeatmapProps> = ({
  logs,
  maxThreshold = 75,
  realtimeTelemetry,
  userRole,
  onLogsMutated
}) => {
  const { isLight } = useTheme();
  const canGovernAudit = isGovernanceAdmin(userRole);

  const [axisMode, setAxisMode] = useState<HeatmapAxisMode>('temporal');
  const [intensityBasis, setIntensityBasis] = useState<HeatmapIntensityBasis>('composite');
  const [trafficFilter, setTrafficFilter] = useState<HeatmapTrafficFilter>('ALL');
  const [functionQuery, setFunctionQuery] = useState<string>('');
  const [selectedCoords, setSelectedCoords] = useState<{ x: number; y: number } | null>(null);
  const [hoveredCoords, setHoveredCoords] = useState<{ x: number; y: number } | null>(null);
  const [exportSuccess, setExportSuccess] = useState(false);

  // Live SHA-256 Audit Ledger Chain Verification State
  const [chainVerifying, setChainVerifying] = useState(false);
  const [chainResult, setChainResult] = useState<ChainVerifyResult | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);

  // Admin Cryptographic Anchor & Legacy Baseline Governance State
  const [anchorStatus, setAnchorStatus] = useState<AuditChainAnchorStatus | null>(null);
  const [govExpanded, setGovExpanded] = useState(false);
  const [baselineCutoffInput, setBaselineCutoffInput] = useState('');
  const [baselineReasonInput, setBaselineReasonInput] = useState('');
  const [baselineBusy, setBaselineBusy] = useState(false);
  const [rotateKeyIdInput, setRotateKeyIdInput] = useState('');
  const [rotateSecretInput, setRotateSecretInput] = useState('');
  const [rotateReasonInput, setRotateReasonInput] = useState('');
  const [rotateBusy, setRotateBusy] = useState(false);
  const [govFeedback, setGovFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchAnchorStatus = async () => {
    if (!canGovernAudit) return;
    try {
      const res = await fetch('/api/v1/audit/anchor-status', {
        headers: getAuthRequestHeaders()
      });
      if (!res.ok) return;
      const data = await res.json();
      if (data?.anchor) {
        setAnchorStatus(data.anchor);
      }
    } catch {
      // ignore background anchor status check failures
    }
  };

  useEffect(() => {
    if (canGovernAudit) {
      fetchAnchorStatus();
    }
  }, [canGovernAudit]);

  const model = useMemo(
    () =>
      buildHeatmapModel({
        logs,
        axisMode,
        intensityBasis,
        trafficFilter,
        functionQuery,
        maxThreshold
      }),
    [logs, axisMode, intensityBasis, trafficFilter, functionQuery, maxThreshold]
  );

  // Keep selected cell valid or default to the hottest cell when data/mode changes
  useEffect(() => {
    if (!model.hottestCell) {
      setSelectedCoords(null);
      return;
    }
    if (
      !selectedCoords ||
      selectedCoords.y >= model.cells.length ||
      selectedCoords.x >= (model.cells[0]?.length || 0)
    ) {
      setSelectedCoords({ x: model.hottestCell.xIndex, y: model.hottestCell.yIndex });
    }
  }, [model, selectedCoords]);

  const activeCoords = hoveredCoords || selectedCoords;
  const inspectedCell: HeatmapCellData | null = useMemo(() => {
    if (!activeCoords) return model.hottestCell;
    return model.cells[activeCoords.y]?.[activeCoords.x] || model.hottestCell;
  }, [activeCoords, model]);

  const handleExportSnapshot = () => {
    const payload = {
      generatedAt: new Date().toISOString(),
      axisMode,
      intensityBasis,
      trafficFilter,
      policyCutoffPct: maxThreshold,
      totalEvaluatedLogs: model.totalEvaluatedLogs,
      totalBlockedLogs: model.totalBlockedLogs,
      topAttackedFunctions: model.rows,
      columns: model.columns,
      coordinates: model.cells.flatMap((row) =>
        row
          .filter((c) => c.totalHits > 0)
          .map((c) => ({
            x: c.xIndex,
            y: c.yIndex,
            column: c.columnLabel,
            functionName: c.functionName,
            totalHits: c.totalHits,
            blockedHits: c.blockedHits,
            allowedHits: c.allowedHits,
            maxRisk: c.maxRisk,
            avgRisk: c.avgRisk,
            avgLatencyMs: c.avgLatencyMs,
            intensity: c.intensity,
            severity: c.severityLabel
          }))
      )
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_heatmap_snapshot_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setExportSuccess(true);
    setTimeout(() => setExportSuccess(false), 2200);
  };

  const handleVerifyAuditChain = async () => {
    setChainVerifying(true);
    setChainError(null);
    try {
      const res = await fetch('/api/v1/audit/verify-chain', {
        headers: getAuthRequestHeaders()
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Audit verification failed');
      }
      setChainResult(data);
      if (data?.suggestedLegacyCutoffMaxId && !baselineCutoffInput) {
        setBaselineCutoffInput(String(data.suggestedLegacyCutoffMaxId));
      }
      if (canGovernAudit) {
        fetchAnchorStatus();
      }
    } catch (err: any) {
      setChainError(err?.message || 'Unable to verify cryptographic chain');
    } finally {
      setChainVerifying(false);
    }
  };

  const handleSealLegacyBaseline = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canGovernAudit || baselineBusy) return;
    setBaselineBusy(true);
    setGovFeedback(null);
    try {
      const parsedCutoff = baselineCutoffInput.trim() ? Number(baselineCutoffInput.trim()) : undefined;
      if (parsedCutoff !== undefined && (!Number.isInteger(parsedCutoff) || parsedCutoff <= 0)) {
        throw new Error('Legacy cutoff max ID must be a positive integer.');
      }
      const res = await fetch('/api/v1/audit/baseline-legacy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthRequestHeaders()
        },
        body: JSON.stringify({
          cutoffMaxId: parsedCutoff,
          reason: baselineReasonInput.trim() || undefined
        })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to seal legacy audit baseline');
      }
      if (data?.verification) {
        setChainResult(data.verification);
      }
      setBaselineCutoffInput('');
      setBaselineReasonInput('');
      setGovFeedback({
        type: 'success',
        message: `Sealed ${data.epoch?.legacyRecordCount ?? 0} archived legacy records (id ≤ ${data.epoch?.legacyCutoffMaxId}) into epoch "${data.epoch?.epochLabel}".`
      });
      await fetchAnchorStatus();
      onLogsMutated?.();
    } catch (err: any) {
      setGovFeedback({
        type: 'error',
        message: err?.message || 'Unable to seal legacy audit baseline'
      });
    } finally {
      setBaselineBusy(false);
    }
  };

  const handleRotateAnchorKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canGovernAudit || rotateBusy) return;
    setRotateBusy(true);
    setGovFeedback(null);
    const trimmedSecret = rotateSecretInput.trim();
    const trimmedKeyId = rotateKeyIdInput.trim();
    const trimmedReason = rotateReasonInput.trim();
    try {
      if (trimmedSecret.length > 0 && trimmedSecret.length < 16) {
        throw new Error('Custom HMAC anchor secret must be at least 16 characters.');
      }
      const res = await fetch('/api/v1/audit/rotate-anchor-key', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthRequestHeaders()
        },
        body: JSON.stringify({
          newKeyId: trimmedKeyId || undefined,
          newSecret: trimmedSecret || undefined,
          reason: trimmedReason || undefined
        })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to rotate anchor key');
      }
      if (data?.anchor) {
        setAnchorStatus(data.anchor);
      }
      if (data?.verification) {
        setChainResult(data.verification);
      }
      setRotateKeyIdInput('');
      setRotateReasonInput('');
      setGovFeedback({
        type: 'success',
        message: `Rotated audit anchor HMAC key to "${data.keyId}" (fingerprint ${data.keyFingerprint}).`
      });
      onLogsMutated?.();
    } catch (err: any) {
      setGovFeedback({
        type: 'error',
        message: err?.message || 'Unable to rotate audit anchor key'
      });
    } finally {
      setRotateSecretInput('');
      setRotateBusy(false);
    }
  };

  const sseLabel =
    realtimeTelemetry?.connectionStatus === 'LIVE_STREAMING'
      ? 'SSE Stream Live'
      : realtimeTelemetry?.connectionStatus === 'POLLING_FALLBACK'
      ? 'Adaptive Poll Fallback'
      : 'SSE Syncing';

  return (
    <section
      id="threat-heatmap-panel"
      aria-label="Real-Time Threat Coordinate Heatmap"
      className="glossy-soc-card rounded-2xl p-5 sm:p-6 relative overflow-hidden"
    >
      {/* Subtle top specular accent */}
      <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent pointer-events-none" />

      {/* Header & Real-Time Telemetry Strip */}
      <div
        className={`flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 mb-5 border-b ${
          isLight ? 'border-slate-200' : 'border-slate-800/80'
        }`}
      >
        <div className="flex items-start gap-3">
          <div
            className={`w-10 h-10 rounded-xl border flex items-center justify-center shrink-0 ${
              isLight
                ? 'bg-rose-50 border-rose-200 text-rose-600'
                : 'bg-rose-500/15 border-rose-500/35 text-rose-400'
            }`}
          >
            <Grid className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h3 className={`text-base font-bold tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Threat Coordinate Heatmap
              </h3>
              <span className="text-slate-400 text-xs" aria-hidden="true">·</span>
              <span className={`text-xs font-mono tabular-nums ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
                {model.totalEvaluatedLogs} events · {model.totalBlockedLogs} intercepted
              </span>
              {realtimeTelemetry && (
                <>
                  <span className="text-slate-400 text-xs" aria-hidden="true">·</span>
                  <span
                    className={`inline-flex items-center gap-1.5 text-xs font-mono tabular-nums ${
                      realtimeTelemetry.connectionStatus === 'LIVE_STREAMING'
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : 'text-amber-600 dark:text-amber-400'
                    }`}
                  >
                    <Radio className="w-3.5 h-3.5" />
                    {sseLabel} ({realtimeTelemetry.streamEventsCount})
                  </span>
                </>
              )}
            </div>
            <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              Intensity-based coordinate mapping across serverless functions and attack intervals to surface targeted endpoints
            </p>
          </div>
        </div>

        {/* Interactive Actions */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            id="btn-verify-audit-chain"
            type="button"
            onClick={handleVerifyAuditChain}
            disabled={chainVerifying}
            className={`glossy-btn flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border whitespace-nowrap shrink-0 cursor-pointer ${
              isLight
                ? 'bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border-emerald-200'
                : 'bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border-emerald-500/35'
            } disabled:opacity-60`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>{chainVerifying ? 'Verifying Chain...' : 'Verify SHA-256 Chain'}</span>
          </button>

          <button
            id="btn-export-heatmap-json"
            type="button"
            onClick={handleExportSnapshot}
            className={`glossy-btn flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border whitespace-nowrap shrink-0 cursor-pointer ${
              exportSuccess
                ? 'bg-emerald-600 text-white border-emerald-500'
                : isLight
                ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-200 border-slate-700'
            }`}
          >
            {exportSuccess ? <Check className="w-3.5 h-3.5" /> : <Download className="w-3.5 h-3.5" />}
            <span>{exportSuccess ? 'Snapshot Saved' : 'Export Matrix'}</span>
          </button>
        </div>
      </div>

      {/* Cryptographic Chain Verification Output Banner (Honest Full vs Epoch vs Discrepancy Reporting) */}
      {(chainResult || chainError) && (
        <div
          id="audit-chain-verify-result"
          className={`mb-4 p-3.5 rounded-xl border text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
            chainError ||
            chainResult?.verificationStatus === 'LEGACY_SNAPSHOT_TAMPERED' ||
            (!chainResult?.chainIntact && chainResult?.verificationStatus !== 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY')
              ? isLight
                ? 'bg-rose-50 border-rose-200 text-rose-800'
                : 'bg-rose-950/30 border-rose-500/40 text-rose-200'
              : chainResult?.verificationStatus === 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY'
              ? isLight
                ? 'bg-amber-50 border-amber-200 text-amber-900'
                : 'bg-amber-950/30 border-amber-500/40 text-amber-200'
              : isLight
              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
              : 'bg-emerald-950/25 border-emerald-500/35 text-emerald-200'
          }`}
        >
          {chainError ? (
            <span>Audit verification error: {chainError}</span>
          ) : chainResult ? (
            <>
              <div className="flex items-center gap-2 flex-wrap">
                {chainResult.chainIntact ? (
                  <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
                ) : chainResult.verificationStatus === 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY' ? (
                  <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                ) : (
                  <ShieldAlert className="w-4 h-4 text-rose-500 shrink-0" />
                )}
                <span className="font-bold">
                  {chainResult.chainIntact
                    ? 'SHA-256 Chain Verified Intact'
                    : chainResult.verificationStatus === 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY'
                    ? 'Modern Epoch Verified · Legacy Records Archived (Full Ledger Unverified)'
                    : chainResult.verificationStatus === 'LEGACY_SNAPSHOT_TAMPERED'
                    ? 'Legacy Snapshot Tampered · Integrity Discrepancy Detected'
                    : 'Chain Discrepancy Detected'}
                </span>
                <span aria-hidden="true">·</span>
                <span className="tabular-nums">
                  {chainResult.verificationStatus === 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY'
                    ? `${chainResult.verifiedEpochCount ?? chainResult.verifiedCount} modern verified · ${chainResult.legacyRecordsCount ?? 0} legacy archived (id ≤ ${chainResult.legacyCutoffMaxId})`
                    : `${chainResult.verifiedCount}/${chainResult.totalChecked} sequential records verified`}
                  {chainResult.anchorKeyId ? ` · Anchor ${chainResult.anchorKeyId}` : ''}
                  {chainResult.genesisVerified === false && chainResult.verificationStatus !== 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY'
                    ? ' · Genesis mismatch'
                    : ''}
                  {chainResult.brokenLinks?.length > 0
                    ? ` · First issue #${chainResult.brokenLinks[0].id} (${chainResult.brokenLinks[0].reason})`
                    : ''}
                </span>
                {chainResult.headHash && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span>Head: {chainResult.headHash.slice(0, 14)}…</span>
                  </>
                )}
              </div>
              <div className="flex items-center gap-2 self-end sm:self-auto">
                {canGovernAudit &&
                  chainResult.suggestedLegacyCutoffMaxId &&
                  !chainResult.chainIntact &&
                  chainResult.verificationStatus !== 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY' && (
                    <button
                      type="button"
                      onClick={() => {
                        setBaselineCutoffInput(String(chainResult.suggestedLegacyCutoffMaxId));
                        setGovExpanded(true);
                      }}
                      className={`px-2.5 py-1 rounded-lg border text-[11px] font-semibold whitespace-nowrap cursor-pointer ${
                        isLight
                          ? 'bg-white border-amber-300 text-amber-800 hover:bg-amber-100'
                          : 'bg-slate-900 border-amber-500/40 text-amber-300 hover:bg-slate-800'
                      }`}
                    >
                      Baseline Legacy ≤#{chainResult.suggestedLegacyCutoffMaxId}
                    </button>
                  )}
                <button
                  type="button"
                  onClick={() => {
                    setChainResult(null);
                    setChainError(null);
                  }}
                  className="text-xs opacity-75 hover:opacity-100 cursor-pointer"
                  aria-label="Dismiss chain verification result"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </>
          ) : null}
        </div>
      )}

      {/* Admin-Only Audit Anchor Key & Legacy Baseline Governance Controls */}
      {canGovernAudit && (
        <div
          id="audit-anchor-governance"
          className={`mb-4 rounded-xl border ${
            isLight ? 'bg-slate-50/80 border-slate-200' : 'bg-slate-950/60 border-slate-800'
          }`}
        >
          <div className="px-4 py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2 flex-wrap font-mono">
              <KeyRound className="w-3.5 h-3.5 text-blue-500 shrink-0" />
              <span className={`font-semibold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Audit Anchor Governance
              </span>
              <span className="text-slate-400" aria-hidden="true">·</span>
              <span className={`tabular-nums ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
                Active Key: {anchorStatus?.activeKeyId || chainResult?.anchorKeyId || 'anchor-v1'}
              </span>
              {anchorStatus?.keyFingerprint && (
                <>
                  <span className="text-slate-400" aria-hidden="true">·</span>
                  <span className="text-slate-500 dark:text-slate-400 tabular-nums">
                    FP: {anchorStatus.keyFingerprint}
                  </span>
                </>
              )}
              {anchorStatus?.activeEpoch && (
                <>
                  <span className="text-slate-400" aria-hidden="true">·</span>
                  <span className="text-amber-600 dark:text-amber-400 tabular-nums">
                    Epoch: {anchorStatus.activeEpoch.epochLabel} ({anchorStatus.activeEpoch.legacyRecordCount} legacy)
                  </span>
                </>
              )}
            </div>
            <button
              id="btn-toggle-audit-governance"
              type="button"
              onClick={() => setGovExpanded((prev) => !prev)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-semibold whitespace-nowrap shrink-0 cursor-pointer ${
                isLight
                  ? 'bg-white border-slate-300 text-slate-700 hover:bg-slate-100'
                  : 'bg-slate-900 border-slate-700 text-slate-200 hover:bg-slate-800'
              }`}
            >
              <span>{govExpanded ? 'Hide Governance' : 'Anchor & Baseline'}</span>
              {govExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          </div>

          {govExpanded && (
            <div className={`px-4 pb-4 pt-3 border-t space-y-4 ${isLight ? 'border-slate-200' : 'border-slate-800'}`}>
              {govFeedback && (
                <div
                  id="audit-governance-feedback"
                  className={`p-2.5 rounded-lg border text-xs font-mono ${
                    govFeedback.type === 'success'
                      ? isLight
                        ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                        : 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'
                      : isLight
                      ? 'bg-rose-50 border-rose-200 text-rose-800'
                      : 'bg-rose-950/30 border-rose-500/40 text-rose-200'
                  }`}
                >
                  {govFeedback.message}
                </div>
              )}

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Seal Legacy Baseline Form */}
                <form
                  onSubmit={handleSealLegacyBaseline}
                  className={`p-3.5 rounded-xl border space-y-2.5 ${
                    isLight ? 'bg-white border-slate-200' : 'bg-slate-900/70 border-slate-800'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-xs font-semibold">
                      <Archive className="w-3.5 h-3.5 text-amber-500" />
                      <span className={isLight ? 'text-slate-900' : 'text-white'}>Seal Legacy Audit Baseline</span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400">Preserves History</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Snapshots historical rows with SHA-256 + HMAC without modifying records, separating legacy history from verified modern epochs.
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <input
                      id="input-baseline-cutoff"
                      type="number"
                      min={1}
                      value={baselineCutoffInput}
                      onChange={(e) => setBaselineCutoffInput(e.target.value)}
                      placeholder="Auto-detect cutoff ID"
                      className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono ${
                        isLight ? 'bg-white border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-slate-100'
                      }`}
                    />
                    <input
                      id="input-baseline-reason"
                      type="text"
                      value={baselineReasonInput}
                      onChange={(e) => setBaselineReasonInput(e.target.value)}
                      placeholder="Audit baseline reason..."
                      className={`px-2.5 py-1.5 rounded-lg border text-xs ${
                        isLight ? 'bg-white border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-slate-100'
                      }`}
                    />
                  </div>
                  <div className="flex justify-end">
                    <button
                      id="btn-seal-legacy-baseline"
                      type="submit"
                      disabled={baselineBusy}
                      className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold whitespace-nowrap cursor-pointer disabled:opacity-60"
                    >
                      {baselineBusy ? 'Sealing Baseline...' : 'Seal Legacy Baseline'}
                    </button>
                  </div>
                </form>

                {/* Rotate Anchor Signing Key Form */}
                <form
                  onSubmit={handleRotateAnchorKey}
                  className={`p-3.5 rounded-xl border space-y-2.5 ${
                    isLight ? 'bg-white border-slate-200' : 'bg-slate-900/70 border-slate-800'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-xs font-semibold">
                      <KeyRound className="w-3.5 h-3.5 text-blue-500" />
                      <span className={isLight ? 'text-slate-900' : 'text-white'}>Rotate Anchor HMAC Key</span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400">
                      {anchorStatus?.previousKeyId ? `Prev: ${anchorStatus.previousKeyId}` : 'Zero-Downtime Ring'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Rotates the server-side HMAC anchor signing key while retaining previous key verification for archived epochs.
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    <input
                      id="input-rotate-key-id"
                      type="text"
                      value={rotateKeyIdInput}
                      onChange={(e) => setRotateKeyIdInput(e.target.value)}
                      placeholder="New Key ID (e.g. anchor-v2)"
                      className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono ${
                        isLight ? 'bg-white border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-slate-100'
                      }`}
                    />
                    <input
                      id="input-rotate-key-secret"
                      type="password"
                      autoComplete="new-password"
                      value={rotateSecretInput}
                      onChange={(e) => setRotateSecretInput(e.target.value)}
                      placeholder="Optional secret (≥16 chars)"
                      className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono ${
                        isLight ? 'bg-white border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-slate-100'
                      }`}
                    />
                    <input
                      id="input-rotate-key-reason"
                      type="text"
                      value={rotateReasonInput}
                      onChange={(e) => setRotateReasonInput(e.target.value)}
                      placeholder="Rotation reason..."
                      className={`px-2.5 py-1.5 rounded-lg border text-xs ${
                        isLight ? 'bg-white border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-slate-100'
                      }`}
                    />
                  </div>
                  <div className="flex justify-end">
                    <button
                      id="btn-rotate-anchor-key"
                      type="submit"
                      disabled={rotateBusy}
                      className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold whitespace-nowrap cursor-pointer disabled:opacity-60"
                    >
                      {rotateBusy ? 'Rotating Key...' : 'Rotate Anchor Key'}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Control Toolbar: Axis Mode, Intensity Calibration, Traffic Filter, Function Search */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 mb-5">
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Coordinate Axis Switcher */}
          <div
            className={`inline-flex items-center p-1 rounded-xl border text-xs ${
              isLight ? 'bg-slate-100 border-slate-200' : 'bg-slate-950/80 border-slate-800'
            }`}
            role="group"
            aria-label="Coordinate Axis Mode"
          >
            <button
              id="btn-heatmap-axis-temporal"
              type="button"
              onClick={() => setAxisMode('temporal')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer ${
                axisMode === 'temporal'
                  ? isLight
                    ? 'bg-white text-slate-900 shadow-xs font-semibold'
                    : 'bg-slate-800 text-white shadow-xs font-semibold'
                  : isLight
                  ? 'text-slate-600 hover:text-slate-900'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              <span>Time × Function</span>
            </button>
            <button
              id="btn-heatmap-axis-vector"
              type="button"
              onClick={() => setAxisMode('vector')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer ${
                axisMode === 'vector'
                  ? isLight
                    ? 'bg-white text-slate-900 shadow-xs font-semibold'
                    : 'bg-slate-800 text-white shadow-xs font-semibold'
                  : isLight
                  ? 'text-slate-600 hover:text-slate-900'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Vector × Function</span>
            </button>
          </div>

          {/* Intensity Basis Switcher */}
          <div
            className={`inline-flex items-center p-1 rounded-xl border text-xs ${
              isLight ? 'bg-slate-100 border-slate-200' : 'bg-slate-950/80 border-slate-800'
            }`}
            role="group"
            aria-label="Intensity Metric"
          >
            {(
              [
                { id: 'composite', label: 'Threat Intensity' },
                { id: 'blocked', label: 'Attack Density' },
                { id: 'volume', label: 'Traffic Volume' }
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setIntensityBasis(opt.id)}
                className={`px-2.5 py-1.5 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  intensityBasis === opt.id
                    ? isLight
                      ? 'bg-white text-blue-700 shadow-xs font-semibold'
                      : 'bg-cyan-500/20 text-cyan-300 font-semibold'
                    : isLight
                    ? 'text-slate-600 hover:text-slate-900'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {/* Traffic Filter */}
          <div
            className={`inline-flex items-center p-1 rounded-xl border text-xs ${
              isLight ? 'bg-slate-100 border-slate-200' : 'bg-slate-950/80 border-slate-800'
            }`}
            role="group"
            aria-label="Event Verdict Filter"
          >
            {(
              [
                { id: 'ALL', label: 'All' },
                { id: 'BLOCKED', label: 'Blocked' },
                { id: 'HIGH_RISK', label: `Risk ≥${maxThreshold}%` }
              ] as const
            ).map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setTrafficFilter(f.id)}
                className={`px-2.5 py-1.5 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  trafficFilter === f.id
                    ? f.id === 'BLOCKED' || f.id === 'HIGH_RISK'
                      ? isLight
                        ? 'bg-rose-600 text-white font-semibold'
                        : 'bg-rose-500/25 text-rose-300 font-semibold'
                      : isLight
                      ? 'bg-white text-slate-900 shadow-xs font-semibold'
                      : 'bg-slate-800 text-white font-semibold'
                    : isLight
                    ? 'text-slate-600 hover:text-slate-900'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {/* Function Search */}
        <div className="relative w-full lg:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            id="input-heatmap-filter"
            type="text"
            value={functionQuery}
            onChange={(e) => setFunctionQuery(e.target.value)}
            placeholder="Filter function or user..."
            className={`w-full pl-8 pr-7 py-1.5 rounded-xl border text-xs font-mono focus:outline-none focus:border-cyan-500 ${
              isLight
                ? 'bg-white border-slate-300 text-slate-900 placeholder:text-slate-400'
                : 'bg-slate-950/80 border-slate-800 text-slate-100 placeholder:text-slate-500'
            }`}
          />
          {functionQuery && (
            <button
              type="button"
              onClick={() => setFunctionQuery('')}
              aria-label="Clear function filter"
              className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-700 dark:hover:text-white cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Main Content Split: Coordinate Matrix (Left 8 cols) + Hotspot Ranking & Inspector (Right 4 cols) */}
      {model.rows.length === 0 ? (
        <div
          className={`p-10 rounded-2xl border text-center space-y-2 ${
            isLight ? 'bg-slate-50 border-slate-200 text-slate-600' : 'bg-slate-950/60 border-slate-800 text-slate-400'
          }`}
        >
          <Activity className="w-7 h-7 mx-auto text-slate-400" />
          <div className={`text-sm font-semibold ${isLight ? 'text-slate-900' : 'text-white'}`}>
            {logs.length === 0
              ? 'No audit invocations recorded yet'
              : 'No coordinates match the active filter'}
          </div>
          <p className="text-xs max-w-md mx-auto">
            {logs.length === 0
              ? 'Execute serverless invocations in the Runtime Interceptor or Developer Console to populate real-time coordinate heat cells.'
              : 'Reset the verdict filter or search query to inspect all active serverless endpoint coordinates.'}
          </p>
          {(trafficFilter !== 'ALL' || functionQuery) && (
            <button
              type="button"
              onClick={() => {
                setTrafficFilter('ALL');
                setFunctionQuery('');
              }}
              className="mt-2 px-4 py-1.5 rounded-lg bg-blue-600 text-white text-xs font-semibold hover:bg-blue-500 cursor-pointer"
            >
              Reset Filters
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
          {/* LEFT: Coordinate Matrix Canvas */}
          <div className="xl:col-span-8 space-y-4">
            <div
              className={`rounded-2xl border p-4 overflow-x-auto ${
                isLight ? 'bg-slate-50/70 border-slate-200' : 'bg-slate-950/65 border-slate-800/90'
              }`}
            >
              {/* Coordinate Grid */}
              <div className="min-w-[640px]">
                {/* X-Axis Column Headers */}
                <div
                  className="grid items-end gap-1.5 mb-2"
                  style={{
                    gridTemplateColumns: `175px repeat(${model.columns.length}, minmax(44px, 1fr))`
                  }}
                >
                  <div className="text-[11px] font-mono font-semibold text-slate-500 dark:text-slate-400 px-1">
                    Function Endpoint ↓ / {axisMode === 'temporal' ? 'Window →' : 'Vector →'}
                  </div>
                  {model.columns.map((col, xIdx) => {
                    const isHoveredCol = activeCoords?.x === xIdx;
                    return (
                      <div
                        key={`${col.label}-${xIdx}`}
                        className={`text-center px-1 pb-1 rounded transition-colors ${
                          isHoveredCol
                            ? isLight
                              ? 'text-blue-700 font-bold'
                              : 'text-cyan-300 font-bold'
                            : 'text-slate-500 dark:text-slate-400'
                        }`}
                      >
                        <div className="text-[10px] font-mono truncate" title={col.label}>
                          {col.label}
                        </div>
                        <div className="text-[9px] font-mono opacity-75 tabular-nums">{col.subLabel}</div>
                      </div>
                    );
                  })}
                </div>

                {/* Matrix Rows */}
                <div className="space-y-1.5">
                  {model.cells.map((rowCells, yIdx) => {
                    const rowSummary = model.rows[yIdx];
                    const isRowActive = activeCoords?.y === yIdx;
                    return (
                      <div
                        key={rowSummary.functionName}
                        className="grid items-center gap-1.5"
                        style={{
                          gridTemplateColumns: `175px repeat(${model.columns.length}, minmax(44px, 1fr))`
                        }}
                      >
                        {/* Y-Axis Function Label */}
                        <button
                          type="button"
                          onClick={() => setFunctionQuery(rowSummary.functionName)}
                          title={`Click to isolate ${rowSummary.functionName} (${rowSummary.blockedHits} blocked / ${rowSummary.totalHits} total)`}
                          className={`text-left px-2 py-1.5 rounded-lg transition-colors cursor-pointer flex items-center justify-between gap-1.5 border ${
                            isRowActive
                              ? isLight
                                ? 'bg-white border-blue-300 text-slate-900 shadow-xs'
                                : 'bg-slate-900 border-cyan-500/40 text-white'
                              : isLight
                              ? 'bg-transparent border-transparent hover:bg-white text-slate-700'
                              : 'bg-transparent border-transparent hover:bg-slate-900/60 text-slate-300'
                          }`}
                        >
                          <span className="text-[11px] font-mono font-semibold truncate">
                            {rowSummary.functionName}
                          </span>
                          <span
                            className={`text-[10px] font-mono tabular-nums shrink-0 ${
                              rowSummary.blockedHits > 0
                                ? 'text-rose-600 dark:text-rose-400 font-bold'
                                : 'text-slate-400'
                            }`}
                          >
                            {rowSummary.blockedHits > 0 ? `${rowSummary.blockedHits}B` : `${rowSummary.totalHits}`}
                          </span>
                        </button>

                        {/* Coordinate Intensity Tiles */}
                        {rowCells.map((cell) => {
                          const isSelected =
                            selectedCoords?.x === cell.xIndex && selectedCoords?.y === cell.yIndex;
                          const visuals = getHeatmapCellVisuals(cell, isLight, isSelected);
                          const displayMetric =
                            cell.totalHits === 0
                              ? '·'
                              : intensityBasis === 'blocked'
                              ? `${cell.blockedHits}`
                              : intensityBasis === 'volume'
                              ? `${cell.totalHits}`
                              : `${cell.maxRisk}%`;

                          return (
                            <button
                              key={`${cell.xIndex}-${cell.yIndex}`}
                              type="button"
                              data-testid={`heatmap-cell-${cell.yIndex}-${cell.xIndex}`}
                              data-function={cell.functionName}
                              data-intensity={cell.intensity}
                              onClick={() => setSelectedCoords({ x: cell.xIndex, y: cell.yIndex })}
                              onMouseEnter={() => setHoveredCoords({ x: cell.xIndex, y: cell.yIndex })}
                              onMouseLeave={() => setHoveredCoords(null)}
                              aria-label={`${cell.functionName} at ${cell.columnLabel}: ${cell.totalHits} hits, ${cell.blockedHits} blocked, peak risk ${cell.maxRisk}% (${cell.severityLabel})`}
                              style={{
                                background: visuals.background,
                                borderColor: visuals.borderColor,
                                color: visuals.textColor,
                                boxShadow: visuals.glowShadow
                              }}
                              className={`glossy-heatmap-cell h-10 rounded-lg border text-[11px] font-mono font-bold tabular-nums flex flex-col items-center justify-center cursor-pointer ${
                                cell.containsLatestLive ? 'heatmap-cell-live' : ''
                              }`}
                            >
                              <span className="leading-none">{displayMetric}</span>
                              {cell.totalHits > 0 && (
                                <span className="text-[9px] font-normal opacity-80 leading-none mt-0.5">
                                  {cell.blockedHits > 0 ? `${cell.blockedHits}/${cell.totalHits}` : `${cell.totalHits} ok`}
                                </span>
                              )}
                            </button>
                          );
                        })}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Calibrated Intensity Legend (Explicit text labels + color) */}
              <div
                className={`mt-4 pt-3 border-t flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] font-mono ${
                  isLight ? 'border-slate-200 text-slate-600' : 'border-slate-800 text-slate-400'
                }`}
              >
                <div className="flex items-center gap-3 flex-wrap">
                  <span>Intensity Scale:</span>
                  <span className="inline-flex items-center gap-1.5">
                    <span
                      className="w-3 h-3 rounded border"
                      style={{ background: 'rgba(16, 185, 129, 0.35)', borderColor: 'rgba(52, 211, 153, 0.5)' }}
                    />
                    Nominal (0–24%)
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <span
                      className="w-3 h-3 rounded border"
                      style={{ background: 'rgba(14, 165, 233, 0.42)', borderColor: 'rgba(56, 189, 248, 0.6)' }}
                    />
                    Guarded (25–49%)
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <span
                      className="w-3 h-3 rounded border"
                      style={{ background: 'rgba(245, 158, 11, 0.48)', borderColor: 'rgba(251, 191, 36, 0.7)' }}
                    />
                    Elevated (50–74%)
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <span
                      className="w-3 h-3 rounded border"
                      style={{ background: 'rgba(244, 63, 94, 0.6)', borderColor: 'rgba(251, 113, 133, 0.8)' }}
                    />
                    Critical (≥{maxThreshold}%)
                  </span>
                </div>
                <span className="tabular-nums">
                  Click any coordinate tile to lock forensic details
                </span>
              </div>
            </div>

            {/* Coordinate Forensic Inspector Panel */}
            {inspectedCell && (
              <div
                id="heatmap-coordinate-inspector"
                className={`rounded-2xl border p-4 ${
                  isLight ? 'bg-white border-slate-200' : 'bg-slate-950/75 border-slate-800'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 mb-3 border-b border-slate-200 dark:border-slate-800">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Crosshair className="w-4 h-4 text-cyan-500 shrink-0" />
                    <span className={`text-xs font-bold font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
                      Coordinate ({inspectedCell.xIndex}, {inspectedCell.yIndex})
                    </span>
                    <span className="text-slate-400 text-xs" aria-hidden="true">·</span>
                    <code className="text-xs font-mono font-semibold text-blue-600 dark:text-cyan-400">
                      /api/{inspectedCell.functionName}
                    </code>
                    <span className="text-slate-400 text-xs" aria-hidden="true">·</span>
                    <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                      {inspectedCell.columnLabel}
                    </span>
                  </div>
                  <span
                    className={`text-xs font-mono font-bold tabular-nums ${
                      inspectedCell.severityLabel === 'Critical'
                        ? 'text-rose-600 dark:text-rose-400'
                        : inspectedCell.severityLabel === 'Elevated'
                        ? 'text-amber-600 dark:text-amber-400'
                        : inspectedCell.severityLabel === 'Guarded'
                        ? 'text-sky-600 dark:text-cyan-400'
                        : 'text-emerald-600 dark:text-emerald-400'
                    }`}
                  >
                    {inspectedCell.severityLabel} Intensity ({Math.round(inspectedCell.intensity * 100)}%)
                  </span>
                </div>

                {inspectedCell.totalHits === 0 ? (
                  <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                    No invocation traffic recorded at coordinate ({inspectedCell.xIndex}, {inspectedCell.yIndex}).
                  </p>
                ) : (
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                      <div>
                        <span className="text-[10px] uppercase text-slate-400 block">Hits (Blocked / Total)</span>
                        <span className={`font-bold tabular-nums ${isLight ? 'text-slate-900' : 'text-white'}`}>
                          <span className="text-rose-500">{inspectedCell.blockedHits}</span> / {inspectedCell.totalHits}
                        </span>
                      </div>
                      <div>
                        <span className="text-[10px] uppercase text-slate-400 block">Peak / Mean Risk</span>
                        <span className="font-bold tabular-nums text-amber-500">
                          {inspectedCell.maxRisk}% / {inspectedCell.avgRisk}%
                        </span>
                      </div>
                      <div>
                        <span className="text-[10px] uppercase text-slate-400 block">Mean Pipeline Latency</span>
                        <span className="font-bold tabular-nums text-cyan-500">
                          {inspectedCell.avgLatencyMs} ms
                        </span>
                      </div>
                      <div>
                        <span className="text-[10px] uppercase text-slate-400 block">Top Principal</span>
                        <span className={`font-bold truncate block ${isLight ? 'text-slate-900' : 'text-white'}`}>
                          {inspectedCell.topPrincipals[0]?.username || 'n/a'} ({inspectedCell.topPrincipals[0]?.count || 0})
                        </span>
                      </div>
                    </div>

                    {/* Recent Audit Records in Selected Coordinate */}
                    <div className="max-h-40 overflow-y-auto divide-y divide-slate-200 dark:divide-slate-800/80 border-t border-slate-200 dark:border-slate-800 pt-2">
                      {inspectedCell.logs.slice(0, 5).map((ev) => (
                        <div key={ev.id} className="py-1.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px] font-mono">
                          <div className="flex items-center gap-2 min-w-0">
                            <span
                              className={`font-bold shrink-0 ${
                                ev.status === 'BLOCKED' ? 'text-rose-500' : 'text-emerald-500'
                              }`}
                            >
                              {ev.status}
                            </span>
                            <span className={`font-semibold shrink-0 ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
                              {ev.username}
                            </span>
                            <span className="text-slate-400 truncate" title={ev.reason}>
                              {ev.reason}
                            </span>
                          </div>
                          <div className="flex items-center gap-2.5 shrink-0 text-slate-400 tabular-nums">
                            <span>Risk {ev.calculated_risk}%</span>
                            <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* RIGHT: Most Frequently Attacked Functions Leaderboard */}
          <div
            className={`xl:col-span-4 rounded-2xl border p-4 space-y-3 ${
              isLight ? 'bg-white border-slate-200' : 'bg-slate-950/65 border-slate-800/90'
            }`}
          >
            <div className="flex items-center justify-between pb-2.5 border-b border-slate-200 dark:border-slate-800">
              <h4 className={`text-xs font-bold uppercase tracking-wider ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Most Targeted Functions
              </h4>
              <span className="text-[11px] font-mono text-slate-400 tabular-nums">
                Top {model.rows.length}
              </span>
            </div>

            <div className="space-y-2.5">
              {model.rows.map((fn, idx) => {
                const isCritical = fn.peakRisk >= maxThreshold || fn.blockRatePct >= 50;
                const barWidth = Math.max(8, fn.attackSharePct || fn.blockRatePct);
                return (
                  <button
                    key={fn.functionName}
                    type="button"
                    onClick={() => setFunctionQuery(functionQuery === fn.functionName ? '' : fn.functionName)}
                    className={`w-full text-left p-2.5 rounded-xl border transition-all cursor-pointer ${
                      functionQuery === fn.functionName
                        ? isLight
                          ? 'bg-blue-50 border-blue-300'
                          : 'bg-cyan-950/35 border-cyan-500/50'
                        : isLight
                        ? 'bg-slate-50 hover:bg-slate-100 border-slate-200'
                        : 'bg-slate-900/55 hover:bg-slate-900 border-slate-800'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 text-xs font-mono">
                      <span className={`font-bold truncate ${isLight ? 'text-slate-900' : 'text-white'}`}>
                        {idx + 1}. {fn.functionName}
                      </span>
                      <span
                        className={`font-bold tabular-nums shrink-0 ${
                          isCritical ? 'text-rose-500' : 'text-amber-500'
                        }`}
                      >
                        {fn.blockedHits} blk / {fn.totalHits}
                      </span>
                    </div>

                    <div className="mt-1.5 h-1.5 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          isCritical ? 'bg-rose-500' : fn.blockedHits > 0 ? 'bg-amber-500' : 'bg-emerald-500'
                        }`}
                        style={{ width: `${Math.min(100, barWidth)}%` }}
                      />
                    </div>

                    <div className="mt-1.5 flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                      <span>{fn.primaryVector}</span>
                      <span>
                        Peak {fn.peakRisk}% · {fn.blockRatePct}% denied
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
