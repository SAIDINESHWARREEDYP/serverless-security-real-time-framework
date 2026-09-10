import React, { useState, useMemo } from 'react';
import { Shield, Search, Filter, RefreshCw, AlertOctagon, CheckCircle, Flame, Activity, Download, Check } from 'lucide-react';
import { SecurityAuditLog } from '../types.ts';

interface AuditLogStreamProps {
  logs: SecurityAuditLog[];
  onRefresh: () => void;
  isRefreshing: boolean;
}

export const AuditLogStream: React.FC<AuditLogStreamProps> = ({
  logs,
  onRefresh,
  isRefreshing
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<'ALL' | 'ALLOWED' | 'BLOCKED'>('ALL');
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const matchesVerdict = filterVerdict === 'ALL' || log.status === filterVerdict;
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        log.username.toLowerCase().includes(q) ||
        log.requested_function.toLowerCase().includes(q) ||
        log.reason.toLowerCase().includes(q);
      return matchesVerdict && matchesSearch;
    });
  }, [logs, filterVerdict, searchQuery]);

  const stats = useMemo(() => {
    const total = logs.length;
    const blocked = logs.filter(l => l.status === 'BLOCKED').length;
    const allowed = logs.filter(l => l.status === 'ALLOWED').length;
    const avgRisk = total > 0 ? Math.round(logs.reduce((acc, curr) => acc + curr.calculated_risk, 0) / total) : 0;
    return { total, blocked, allowed, avgRisk };
  }, [logs]);

  const handleDownloadCSV = () => {
    if (filteredLogs.length === 0) return;

    const escapeCsv = (val: string | number | undefined | null) => {
      const str = String(val ?? '');
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const headers = [
      'Log ID',
      'Timestamp (ISO)',
      'Local Time',
      'Principal (Username)',
      'Requested Function Path',
      'Calculated Risk (%)',
      'Verdict',
      'Mitigation Heuristics / Reason'
    ];

    const rows = filteredLogs.map((log) => [
      escapeCsv(log.id),
      escapeCsv(log.timestamp),
      escapeCsv(new Date(log.timestamp).toLocaleString()),
      escapeCsv(log.username),
      escapeCsv(log.requested_function),
      escapeCsv(log.calculated_risk),
      escapeCsv(log.status),
      escapeCsv(log.reason)
    ]);

    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;

    const dateStr = new Date().toISOString().slice(0, 10);
    const filterTag = filterVerdict !== 'ALL' ? `_${filterVerdict.toLowerCase()}` : '';
    link.setAttribute('download', `security_audit_logs${filterTag}_${dateStr}.csv`);

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloadSuccess(true);
    setTimeout(() => setDownloadSuccess(false), 2200);
  };

  return (
    <div className="bg-[#131c2e] border border-[#223452] p-5 rounded-md flex flex-col h-full font-mono">
      {/* Header and Controls */}
      <div className="border-b border-[#223452] pb-3 mb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#00ff87]" />
            Real-Time Framework Audit Streams
          </h3>
          <p className="text-[11px] text-[#6b7c96] mt-0.5">
            Cryptographic ledger tracking identity tokens, RBAC validations & sequential flow rules
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            id="btn-download-csv"
            onClick={handleDownloadCSV}
            disabled={filteredLogs.length === 0}
            className={`px-2.5 py-1.5 rounded bg-[#090d16] hover:bg-[#1a273f] border border-[#223452] text-xs flex items-center gap-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
              downloadSuccess ? 'text-[#00ff87] border-[#00ff87]/50' : 'text-[#94a3b8] hover:text-[#00ff87]'
            }`}
            title={
              filteredLogs.length > 0
                ? `Export ${filteredLogs.length} currently filtered logs to CSV`
                : 'No logs currently match filters to download'
            }
          >
            {downloadSuccess ? (
              <>
                <Check className="w-3.5 h-3.5 text-[#00ff87]" />
                <span className="text-[#00ff87]">Downloaded!</span>
              </>
            ) : (
              <>
                <Download className="w-3.5 h-3.5 text-[#00ff87]" />
                <span>Download CSV {filteredLogs.length > 0 ? `(${filteredLogs.length})` : ''}</span>
              </>
            )}
          </button>

          <button
            id="btn-refresh-logs"
            onClick={onRefresh}
            disabled={isRefreshing}
            className="px-2.5 py-1.5 rounded bg-[#090d16] hover:bg-[#1a273f] text-[#94a3b8] hover:text-white border border-[#223452] text-xs flex items-center gap-1 transition-colors disabled:opacity-50"
            title="Refresh logs from database"
          >
            <RefreshCw className={`w-3 h-3 text-[#00d2ff] ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
        <div className="bg-[#090d16] border border-[#223452] p-2.5 rounded">
          <div className="text-[10px] text-[#6b7c96] uppercase flex items-center justify-between">
            <span>Total Streams</span>
            <Activity className="w-3 h-3 text-[#00d2ff]" />
          </div>
          <div className="text-lg font-bold text-white mt-1">{stats.total}</div>
        </div>

        <div className="bg-[#090d16] border border-[#223452] p-2.5 rounded">
          <div className="text-[10px] text-[#6b7c96] uppercase flex items-center justify-between">
            <span>Allowed</span>
            <CheckCircle className="w-3 h-3 text-[#00ff87]" />
          </div>
          <div className="text-lg font-bold text-[#00ff87] mt-1">{stats.allowed}</div>
        </div>

        <div className="bg-[#090d16] border border-[#223452] p-2.5 rounded">
          <div className="text-[10px] text-[#6b7c96] uppercase flex items-center justify-between">
            <span>Intercepted</span>
            <AlertOctagon className="w-3 h-3 text-[#ff4a6b]" />
          </div>
          <div className="text-lg font-bold text-[#ff4a6b] mt-1">{stats.blocked}</div>
        </div>

        <div className="bg-[#090d16] border border-[#223452] p-2.5 rounded">
          <div className="text-[10px] text-[#6b7c96] uppercase flex items-center justify-between">
            <span>Avg Risk</span>
            <Flame className="w-3 h-3 text-amber-400" />
          </div>
          <div className="text-lg font-bold text-amber-400 mt-1">{stats.avgRisk}%</div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row gap-2 mb-3">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 text-[#6b7c96] absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search principal, route, or heuristics..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-[#090d16] border border-[#223452] text-white text-xs rounded focus:outline-none focus:border-[#00d2ff]"
          />
        </div>

        <div className="flex items-center gap-1 text-xs">
          <span className="text-[10px] text-[#6b7c96] uppercase mr-1 hidden sm:inline">Verdict:</span>
          {(['ALL', 'ALLOWED', 'BLOCKED'] as const).map((v) => (
            <button
              key={v}
              onClick={() => setFilterVerdict(v)}
              className={`px-2 py-1 rounded text-[11px] font-bold border transition-colors ${
                filterVerdict === v
                  ? v === 'ALLOWED'
                    ? 'bg-[#00ff87]/20 border-[#00ff87] text-[#00ff87]'
                    : v === 'BLOCKED'
                    ? 'bg-[#ff4a6b]/20 border-[#ff4a6b] text-[#ff4a6b]'
                    : 'bg-[#00d2ff]/20 border-[#00d2ff] text-[#00d2ff]'
                  : 'bg-[#090d16] border-[#223452] text-[#94a3b8] hover:border-[#334e78]'
              }`}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {/* Table Container */}
      <div className="overflow-x-auto flex-1 max-h-[520px] rounded border border-[#1e293b]">
        <table className="w-full border-collapse text-left text-xs">
          <thead className="bg-[#090d16] sticky top-0 z-10">
            <tr className="border-b border-[#1e293b] text-[#6b7c96] uppercase text-[10px] tracking-wider">
              <th className="p-3">Time</th>
              <th className="p-3">Principal</th>
              <th className="p-3">Function Path</th>
              <th className="p-3">Computed Risk</th>
              <th className="p-3">Verdict</th>
              <th className="p-3">Engine Mitigation Heuristics</th>
            </tr>
          </thead>
          <tbody id="logs" className="divide-y divide-[#1e293b]">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center text-[#4a5d78] py-12">
                  {logs.length === 0
                    ? 'No operational triggers executed yet. Fire the pipeline.'
                    : 'No audit records match the selected filter query.'}
                </td>
              </tr>
            ) : (
              filteredLogs.map((item) => {
                const isBlocked = item.status === 'BLOCKED';
                const formattedTime = new Date(item.timestamp).toLocaleTimeString();
                const isHighRisk = item.calculated_risk >= 70;

                return (
                  <tr
                    key={item.id}
                    className="hover:bg-[#1a273f]/60 transition-colors"
                  >
                    <td className="p-3 text-[#94a3b8] whitespace-nowrap">{formattedTime}</td>
                    <td className="p-3 font-semibold text-white whitespace-nowrap">
                      {item.username}
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <code className="text-[#00d2ff] bg-[#00d2ff]/10 px-1.5 py-0.5 rounded border border-[#00d2ff]/20">
                        {item.requested_function}
                      </code>
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span
                          className={`font-bold ${
                            isHighRisk ? 'text-[#ff4a6b]' : 'text-[#00ff87]'
                          }`}
                        >
                          {item.calculated_risk}%
                        </span>
                        <div className="w-12 h-1.5 bg-[#090d16] rounded-full overflow-hidden border border-[#223452]">
                          <div
                            className={`h-full ${
                              isHighRisk ? 'bg-[#ff4a6b]' : 'bg-[#00ff87]'
                            }`}
                            style={{ width: `${Math.min(item.calculated_risk, 100)}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          isBlocked
                            ? 'bg-[#ff4a6b]/15 text-[#ff4a6b] border border-[#ff4a6b]/30'
                            : 'bg-[#00ff87]/15 text-[#00ff87] border border-[#00ff87]/30'
                        }`}
                      >
                        {item.status}
                      </span>
                    </td>
                    <td className="p-3 text-[#a0aec0] leading-relaxed max-w-xs sm:max-w-md">
                      {item.reason}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
