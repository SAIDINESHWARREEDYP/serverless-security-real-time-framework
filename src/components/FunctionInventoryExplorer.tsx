import React, { useState, useEffect, useMemo } from 'react';
import {
  Layers,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Play,
  Clock,
  Cpu,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ChevronRight,
  RefreshCw,
  ExternalLink,
  ChevronLeft
} from 'lucide-react';
import { SecurityAuditLog } from '../types.ts';
import { InvocationDetailsModal } from './InvocationDetailsModal.tsx';
import { useTheme } from '../context/ThemeContext.tsx';

interface FunctionEntity {
  id: string;
  name: string;
  slug: string;
  service_name: string;
  runtime: string;
  max_memory_mb: number;
  timeout_seconds: number;
  is_active: boolean;
  required_permission?: string;
}

interface FunctionInventoryExplorerProps {
  logs: SecurityAuditLog[];
  onFireFunction?: (functionSlug: string) => Promise<void>;
  isFiring?: boolean;
}

export const FunctionInventoryExplorer: React.FC<FunctionInventoryExplorerProps> = ({
  logs,
  onFireFunction,
  isFiring = false
}) => {
  const { isLight } = useTheme();
  const [activeTab, setActiveTab] = useState<'inventory' | 'explorer'>('inventory');
  const [functions, setFunctions] = useState<FunctionEntity[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ALLOWED' | 'BLOCKED'>('ALL');
  const [selectedLog, setSelectedLog] = useState<SecurityAuditLog | null>(null);

  // Pagination for invocation explorer
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 8;

  const fetchFunctions = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/v1/verify/functions');
      if (res.ok) {
        const data = await res.json();
        setFunctions(data.functions || []);
      }
    } catch {
      // fallback
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchFunctions();
  }, []);

  // Filter functions
  const filteredFunctions = useMemo(() => {
    return functions.filter((fn) => {
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return fn.name.toLowerCase().includes(q) || fn.slug.toLowerCase().includes(q) || fn.service_name.toLowerCase().includes(q);
    });
  }, [functions, searchQuery]);

  // Filter logs for Invocation Explorer
  const filteredLogs = useMemo(() => {
    return logs.filter((l) => {
      if (statusFilter !== 'ALL' && l.status !== statusFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return l.requested_function.toLowerCase().includes(q) || l.username.toLowerCase().includes(q) || l.reason.toLowerCase().includes(q);
      }
      return true;
    });
  }, [logs, statusFilter, searchQuery]);

  // Paginated logs
  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / pageSize));
  const paginatedLogs = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredLogs.slice(start, start + pageSize);
  }, [filteredLogs, currentPage, pageSize]);

  return (
    <div className="space-y-6 font-mono">
      {/* Top Navigation & Sub-views */}
      <div className={`p-4 rounded-2xl border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 shadow-xs ${
        isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'
      }`}>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-500 shrink-0">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
                Serverless Function Catalog &amp; Invocation Explorer
              </h2>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/30 font-semibold">
                {functions.length} Catalog Endpoints
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Granular inspection of microservices, worker boundaries, and verified request traces
            </p>
          </div>
        </div>

        {/* View Tabs Switcher */}
        <div className={`flex border rounded-xl p-1 text-xs self-start sm:self-auto ${
          isLight ? 'bg-slate-100 border-slate-200' : 'bg-[#090d16] border-[#223452]'
        }`}>
          <button
            type="button"
            onClick={() => setActiveTab('inventory')}
            className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${
              activeTab === 'inventory'
                ? isLight ? 'bg-white text-blue-600 shadow-xs' : 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Function Catalog ({functions.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('explorer')}
            className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${
              activeTab === 'explorer'
                ? isLight ? 'bg-white text-blue-600 shadow-xs' : 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Invocation Explorer ({logs.length})
          </button>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div className={`p-4 rounded-2xl border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 ${
        isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/40 border-slate-800'
      }`}>
        <div className={`flex items-center gap-2 px-3 py-2 rounded-xl border text-xs w-full sm:max-w-md ${
          isLight ? 'bg-white border-slate-300' : 'bg-slate-950 border-slate-800'
        }`}>
          <Search className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            placeholder={activeTab === 'inventory' ? 'Search function name, slug, or service...' : 'Search invocations by function, caller, reason...'}
            className="w-full bg-transparent border-none outline-none text-xs"
          />
          {searchQuery && (
            <button type="button" onClick={() => setSearchQuery('')} className="text-slate-400 hover:text-white text-xs">
              ✕
            </button>
          )}
        </div>

        {activeTab === 'explorer' && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Filter Verdict:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value as any);
                setCurrentPage(1);
              }}
              className={`text-xs px-2.5 py-1.5 rounded-xl border outline-none ${
                isLight ? 'bg-white border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-800 text-slate-200'
              }`}
            >
              <option value="ALL">All Invocations ({logs.length})</option>
              <option value="ALLOWED">Allowed Only</option>
              <option value="BLOCKED">Blocked / Mitigated</option>
            </select>
          </div>
        )}
      </div>

      {/* TAB 1: FUNCTION CATALOG INVENTORY */}
      {activeTab === 'inventory' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredFunctions.map((fn) => (
            <div
              key={fn.id}
              className={`p-4 rounded-2xl border transition-all flex flex-col justify-between gap-3 ${
                isLight
                  ? 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'
                  : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700 shadow-sm'
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-semibold truncate">
                    {fn.service_name}
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
                    {fn.is_active ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>

                <h3 className="text-sm font-bold tracking-tight text-slate-100">{fn.name}</h3>
                <code className="text-[11px] text-blue-400 block mt-0.5">/api/{fn.slug}</code>

                <div className="grid grid-cols-3 gap-2 mt-3 pt-3 border-t border-slate-800/60 text-[10px] text-slate-400">
                  <div>
                    <span className="block text-slate-500 font-semibold">Runtime</span>
                    <span className="text-slate-300 font-bold">{fn.runtime}</span>
                  </div>
                  <div>
                    <span className="block text-slate-500 font-semibold">Memory</span>
                    <span className="text-slate-300 font-bold">{fn.max_memory_mb} MB</span>
                  </div>
                  <div>
                    <span className="block text-slate-500 font-semibold">Timeout</span>
                    <span className="text-slate-300 font-bold">{fn.timeout_seconds}s</span>
                  </div>
                </div>

                {fn.required_permission && (
                  <div className="mt-2 text-[10px] text-slate-400">
                    Required Clearance: <span className="font-semibold text-purple-400">{fn.required_permission}</span>
                  </div>
                )}
              </div>

              <div className="pt-2 border-t border-slate-800/40 flex items-center justify-between">
                <span className="text-[10px] text-slate-500 font-mono">
                  {logs.filter(l => l.requested_function.includes(fn.slug)).length} Invocations logged
                </span>

                {onFireFunction && (
                  <button
                    type="button"
                    onClick={() => onFireFunction(fn.slug)}
                    disabled={isFiring || !fn.is_active}
                    className="px-3 py-1.5 rounded-xl text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50 transition-all flex items-center gap-1.5"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>Test Invoke</span>
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 2: INVOCATION EXPLORER */}
      {activeTab === 'explorer' && (
        <div className="space-y-4">
          <div className="rounded-2xl border border-slate-800 overflow-hidden shadow-sm">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className={isLight ? 'bg-slate-100/90 text-slate-700' : 'bg-slate-900/90 text-slate-300'}>
                  <th className="p-3 font-bold border-b border-slate-800">#</th>
                  <th className="p-3 font-bold border-b border-slate-800">Target Function</th>
                  <th className="p-3 font-bold border-b border-slate-800">Caller</th>
                  <th className="p-3 font-bold border-b border-slate-800 text-center">Risk Score</th>
                  <th className="p-3 font-bold border-b border-slate-800 text-center">Verdict</th>
                  <th className="p-3 font-bold border-b border-slate-800">Overhead</th>
                  <th className="p-3 font-bold border-b border-slate-800">Timestamp</th>
                  <th className="p-3 font-bold border-b border-slate-800 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {paginatedLogs.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-slate-500 text-xs">
                      No matching invocation traces found in active audit ledger.
                    </td>
                  </tr>
                ) : (
                  paginatedLogs.map((log) => {
                    const isBlocked = log.status === 'BLOCKED';
                    return (
                      <tr
                        key={log.id}
                        onClick={() => setSelectedLog(log)}
                        className={`cursor-pointer transition-colors ${
                          isLight ? 'hover:bg-slate-50' : 'hover:bg-slate-800/40'
                        }`}
                      >
                        <td className="p-3 text-slate-500">#{log.id}</td>
                        <td className="p-3 font-bold text-blue-400 truncate max-w-[180px]">
                          {log.requested_function.replace(/^\/api\//, '')}
                        </td>
                        <td className="p-3 text-slate-300 font-semibold">{log.username}</td>
                        <td className="p-3 text-center">
                          <span className={`font-bold ${
                            log.calculated_risk >= 75 ? 'text-rose-400' : log.calculated_risk >= 35 ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            {log.calculated_risk}%
                          </span>
                        </td>
                        <td className="p-3 text-center">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                            isBlocked
                              ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                              : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                          }`}>
                            {log.status}
                          </span>
                        </td>
                        <td className="p-3 text-slate-400">
                          {(log.verification_latency_ms || 0.285).toFixed(3)} ms
                        </td>
                        <td className="p-3 text-slate-500 text-[11px]">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="p-3 text-right">
                          <span className="text-[11px] text-blue-400 hover:text-blue-300 font-bold inline-flex items-center gap-1">
                            Inspect 15-Steps <ChevronRight className="w-3.5 h-3.5" />
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div className="flex items-center justify-between text-xs text-slate-400 px-1">
            <span>
              Showing Page <strong className="text-white">{currentPage}</strong> of <strong className="text-white">{totalPages}</strong> ({filteredLogs.length} records)
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="px-3 py-1.5 rounded-xl border border-slate-800 bg-slate-900 hover:bg-slate-800 disabled:opacity-40 transition-all flex items-center gap-1"
              >
                <ChevronLeft className="w-3.5 h-3.5" /> Previous
              </button>
              <button
                type="button"
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="px-3 py-1.5 rounded-xl border border-slate-800 bg-slate-900 hover:bg-slate-800 disabled:opacity-40 transition-all flex items-center gap-1"
              >
                Next <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Invocation Details Modal */}
      <InvocationDetailsModal
        isOpen={Boolean(selectedLog)}
        onClose={() => setSelectedLog(null)}
        log={selectedLog}
      />
    </div>
  );
};
