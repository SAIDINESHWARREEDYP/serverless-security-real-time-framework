import React, { useState, useEffect, useMemo } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  User,
  Filter,
  Search,
  Plus,
  RefreshCw,
  Check,
  X,
  FileText,
  ChevronRight,
  ChevronLeft
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext.tsx';

export interface IncidentCase {
  id: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
  created_at: string;
  root_cause?: string;
  mitigation_steps?: string;
  assigned_to?: string;
}

interface IncidentManagementConsoleProps {
  currentUsername: string;
}

export const IncidentManagementConsole: React.FC<IncidentManagementConsoleProps> = ({
  currentUsername
}) => {
  const { isLight } = useTheme();
  const [incidents, setIncidents] = useState<IncidentCase[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED'>('ALL');
  const [selectedIncident, setSelectedIncident] = useState<IncidentCase | null>(null);

  // New incident modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('HIGH');
  const [newRootCause, setNewRootCause] = useState('');
  const [newMitigation, setNewMitigation] = useState('');
  const [newAssignee, setNewAssignee] = useState(currentUsername || 'secops_admin');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [actionMsg, setActionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 5;

  const fetchIncidents = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/v1/incidents');
      if (res.ok) {
        const data = await res.json();
        setIncidents(data.incidents || []);
      }
    } catch {
      // fallback
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    setIsSubmitting(true);
    setActionMsg(null);

    try {
      const token = localStorage.getItem('auth_jwt_token');
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/v1/incidents', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          title: newTitle.trim(),
          severity: newSeverity,
          root_cause: newRootCause || 'Identified via automated threat sentinel telemetry',
          mitigation_steps: newMitigation || 'Quarantine applied to target identity token',
          assigned_to: newAssignee
        })
      });

      if (!res.ok) throw new Error('Failed to register incident');
      setActionMsg({ type: 'success', text: 'New incident registered into SecOps command log.' });
      setNewTitle('');
      setNewRootCause('');
      setNewMitigation('');
      setShowCreateModal(false);
      fetchIncidents();
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message || 'Failed to create incident' });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUpdateStatus = async (id: string, newStatus: string) => {
    try {
      const token = localStorage.getItem('auth_jwt_token');
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`/api/v1/incidents/${id}`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ status: newStatus })
      });

      if (res.ok) {
        setActionMsg({ type: 'success', text: `Incident ${id} updated to status [${newStatus}].` });
        fetchIncidents();
      }
    } catch {
      setActionMsg({ type: 'error', text: 'Failed to update incident status' });
    }
  };

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
      if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return inc.title.toLowerCase().includes(q) || inc.id.toLowerCase().includes(q) || (inc.assigned_to && inc.assigned_to.toLowerCase().includes(q));
      }
      return true;
    });
  }, [incidents, severityFilter, statusFilter, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filteredIncidents.length / pageSize));
  const paginatedIncidents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredIncidents.slice(start, start + pageSize);
  }, [filteredIncidents, currentPage, pageSize]);

  return (
    <div className="space-y-6 font-mono">
      {/* Top Header */}
      <div className={`p-4 rounded-2xl border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 shadow-xs ${
        isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'
      }`}>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-500 shrink-0">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
                Incident Response &amp; Threat Containment Center
              </h2>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30 font-semibold">
                {incidents.filter(i => i.status === 'OPEN' || i.status === 'INVESTIGATING').length} Active Incidents
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Triage critical security alerts, assign containment actions, and document mitigation steps
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            type="button"
            onClick={fetchIncidents}
            disabled={isLoading}
            className={`p-2 rounded-xl border transition-all ${
              isLight ? 'bg-white hover:bg-slate-100 border-slate-200' : 'bg-slate-900 hover:bg-slate-800 border-slate-800'
            }`}
          >
            <RefreshCw className={`w-4 h-4 text-slate-400 ${isLoading ? 'animate-spin' : ''}`} />
          </button>

          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="px-3.5 py-2 rounded-xl text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white flex items-center gap-1.5 shadow-sm transition-all"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Open Incident</span>
          </button>
        </div>
      </div>

      {actionMsg && (
        <div className={`p-3 rounded-xl border text-xs flex items-center justify-between ${
          actionMsg.type === 'success'
            ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
            : 'bg-rose-950/20 border-rose-500/40 text-rose-300'
        }`}>
          <span>{actionMsg.text}</span>
          <button type="button" onClick={() => setActionMsg(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Filter and Search Toolbar */}
      <div className={`p-4 rounded-2xl border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 ${
        isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/40 border-slate-800'
      }`}>
        <div className={`flex items-center gap-2 px-3 py-2 rounded-xl border text-xs w-full sm:max-w-xs ${
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
            placeholder="Search incident ID, title, analyst..."
            className="w-full bg-transparent border-none outline-none text-xs"
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value as any);
                setCurrentPage(1);
              }}
              className={`text-xs px-2.5 py-1.5 rounded-xl border outline-none ${
                isLight ? 'bg-white border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-800 text-slate-200'
              }`}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Status:</span>
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
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="CONTAINED">Contained</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>
        </div>
      </div>

      {/* Incidents List */}
      <div className="space-y-3">
        {paginatedIncidents.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs border border-slate-800 rounded-2xl bg-slate-900/20">
            No active incidents matching selected search and filter criteria.
          </div>
        ) : (
          paginatedIncidents.map((inc) => (
            <div
              key={inc.id}
              className={`p-4 rounded-2xl border transition-all flex flex-col md:flex-row md:items-center md:justify-between gap-4 ${
                inc.severity === 'CRITICAL'
                  ? 'bg-rose-950/15 border-rose-500/30'
                  : inc.severity === 'HIGH'
                  ? 'bg-amber-950/15 border-amber-500/30'
                  : isLight
                  ? 'bg-white border-slate-200'
                  : 'bg-slate-900/50 border-slate-800'
              }`}
            >
              <div className="space-y-1.5 min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-bold text-xs text-slate-400 font-mono">[{inc.id}]</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                    inc.severity === 'CRITICAL'
                      ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 animate-pulse'
                      : inc.severity === 'HIGH'
                      ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                      : 'bg-blue-500/20 text-blue-400 border-blue-500/40'
                  }`}>
                    {inc.severity}
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                    inc.status === 'CONTAINED'
                      ? 'bg-purple-500/20 text-purple-400 border-purple-500/40'
                      : inc.status === 'RESOLVED'
                      ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                      : 'bg-slate-800 text-slate-300 border-slate-700'
                  }`}>
                    {inc.status}
                  </span>
                  <span className="text-[10px] text-slate-500">
                    Opened: {new Date(inc.created_at).toLocaleDateString()}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-slate-100">{inc.title}</h3>
                {inc.root_cause && (
                  <p className="text-xs text-slate-400 line-clamp-1">
                    <strong className="text-slate-300">Root Cause:</strong> {inc.root_cause}
                  </p>
                )}
                {inc.mitigation_steps && (
                  <p className="text-xs text-slate-400 line-clamp-1">
                    <strong className="text-slate-300">Mitigation:</strong> {inc.mitigation_steps}
                  </p>
                )}
              </div>

              {/* Status Actions */}
              <div className="flex items-center gap-2 shrink-0 self-start md:self-center">
                <span className="text-[11px] text-slate-400 hidden sm:inline">
                  Assigned: <strong className="text-slate-200">{inc.assigned_to}</strong>
                </span>

                <select
                  value={inc.status}
                  onChange={(e) => handleUpdateStatus(inc.id, e.target.value)}
                  className={`text-xs px-2.5 py-1.5 rounded-xl border outline-none font-semibold ${
                    isLight ? 'bg-slate-100 border-slate-300 text-slate-800' : 'bg-slate-800 border-slate-700 text-slate-200'
                  }`}
                >
                  <option value="OPEN">Mark Open</option>
                  <option value="INVESTIGATING">Mark Investigating</option>
                  <option value="CONTAINED">Mark Contained</option>
                  <option value="RESOLVED">Mark Resolved</option>
                  <option value="FALSE_POSITIVE">False Positive</option>
                </select>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination Controls */}
      <div className="flex items-center justify-between text-xs text-slate-400 px-1 pt-2">
        <span>
          Showing Page <strong className="text-white">{currentPage}</strong> of <strong className="text-white">{totalPages}</strong> ({filteredIncidents.length} incidents)
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="px-3 py-1.5 rounded-xl border border-slate-800 bg-slate-900 hover:bg-slate-800 disabled:opacity-40 transition-all flex items-center gap-1"
          >
            <ChevronLeft className="w-3.5 h-3.5" /> Prev
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

      {/* Create Incident Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <div className="bg-[#0c1222] border border-slate-800 p-6 rounded-3xl w-full max-w-lg space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-rose-500" />
                Register New Security Incident
              </h3>
              <button type="button" onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-white">
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Incident Title</label>
                <input
                  type="text"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Malicious IMDS Link-Local SSRF Probe"
                  className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white outline-none"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Severity Tier</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as any)}
                    className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white outline-none"
                  >
                    <option value="CRITICAL">Critical Tier 4</option>
                    <option value="HIGH">High Tier 3</option>
                    <option value="MEDIUM">Medium Tier 2</option>
                    <option value="LOW">Low Tier 1</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Assigned Investigator</label>
                  <input
                    type="text"
                    value={newAssignee}
                    onChange={(e) => setNewAssignee(e.target.value)}
                    className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Root Cause Analysis</label>
                <textarea
                  rows={2}
                  value={newRootCause}
                  onChange={(e) => setNewRootCause(e.target.value)}
                  placeholder="Observed threat indicators, IP origin, payload details..."
                  className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white outline-none resize-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Mitigation &amp; Containment Action</label>
                <textarea
                  rows={2}
                  value={newMitigation}
                  onChange={(e) => setNewMitigation(e.target.value)}
                  placeholder="Actions taken to isolate or neutralize the threat vector..."
                  className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white outline-none resize-none"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-xl border border-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || !newTitle.trim()}
                  className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold disabled:opacity-50"
                >
                  {isSubmitting ? 'Registering...' : 'Register Incident'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
