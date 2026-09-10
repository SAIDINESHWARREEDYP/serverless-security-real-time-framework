import React, { useState } from 'react';
import { X, ArrowRight, ShieldCheck, Database, Plus, Trash2, Key, Users, Layers, AlertTriangle } from 'lucide-react';
import { User, FunctionRule } from '../types.ts';

interface SecurityArchitectureModalProps {
  isOpen: boolean;
  onClose: () => void;
  users: User[];
  rules: FunctionRule[];
  onAddRule: (current: string, next: string) => Promise<void>;
  onDeleteRule: (id: number) => Promise<void>;
}

export const SecurityArchitectureModal: React.FC<SecurityArchitectureModalProps> = ({
  isOpen,
  onClose,
  users,
  rules,
  onAddRule,
  onDeleteRule
}) => {
  const [currentFunc, setCurrentFunc] = useState('');
  const [nextFunc, setNextFunc] = useState('');
  const [isAdding, setIsAdding] = useState(false);

  if (!isOpen) return null;

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentFunc || !nextFunc) return;
    setIsAdding(true);
    await onAddRule(currentFunc.trim(), nextFunc.trim());
    setCurrentFunc('');
    setNextFunc('');
    setIsAdding(false);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 font-mono">
      <div className="bg-[#0f172a] border border-[#334e78] rounded-lg max-w-4xl w-full max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
        {/* Modal Header */}
        <div className="p-4 border-b border-[#1e293b] flex items-center justify-between bg-[#131c2e]">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-[#00d2ff]" />
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                SQL Schema, Storage &amp; Architectural Pipeline
              </h2>
              <p className="text-[11px] text-[#6b7c96]">
                Cloudflare D1 Live Storage &amp; Interceptor Rule Definition Matrices
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-[#6b7c96] hover:text-white rounded hover:bg-[#1e293b] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-[#cbd5e1]">
          {/* Visual Architecture Diagram */}
          <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
            <h3 className="text-[#00d2ff] font-bold uppercase text-xs mb-3 flex items-center gap-1.5">
              <Layers className="w-4 h-4" />
              Multi-Stage Serverless Verification Pipeline
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-center">
              <div className="p-3 bg-[#131c2e] border border-[#223452] rounded flex flex-col justify-between">
                <div className="text-[10px] text-[#6b7c96] uppercase font-bold">Stage 1</div>
                <div className="font-bold text-white my-1">Token Authentication</div>
                <div className="text-[10px] text-[#94a3b8]">Bearer token validation against users table</div>
              </div>

              <div className="p-3 bg-[#131c2e] border border-[#223452] rounded flex flex-col justify-between">
                <div className="text-[10px] text-[#6b7c96] uppercase font-bold">Stage 2</div>
                <div className="font-bold text-[#00d2ff] my-1">RBAC Evaluation</div>
                <div className="text-[10px] text-[#94a3b8]">Admin: Any | Dev: Metrics/Logs | Guest: Metrics</div>
              </div>

              <div className="p-3 bg-[#131c2e] border border-[#223452] rounded flex flex-col justify-between">
                <div className="text-[10px] text-[#6b7c96] uppercase font-bold">Stage 3</div>
                <div className="font-bold text-amber-400 my-1">Sequential Flow Analysis</div>
                <div className="text-[10px] text-[#94a3b8]">Valid sequence match or +40% penalty</div>
              </div>

              <div className="p-3 bg-[#131c2e] border border-[#223452] rounded flex flex-col justify-between">
                <div className="text-[10px] text-[#6b7c96] uppercase font-bold">Stage 4</div>
                <div className="font-bold text-[#ff4a6b] my-1">Firewall Intercept</div>
                <div className="text-[10px] text-[#94a3b8]">Cutoff &gt;= 75% drops transit connection</div>
              </div>
            </div>
          </div>

          {/* Table: function_rules & Sequence Flow Graph */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Rules Graph and List */}
            <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-white font-bold uppercase text-[11px] flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-[#00ff87]" />
                    TABLE: function_rules (Allowed Paths)
                  </h4>
                  <span className="text-[10px] text-[#6b7c96]">{rules.length} Active Rules</span>
                </div>

                {/* Flow Graph Preview */}
                <div className="p-2.5 bg-[#131c2e] rounded border border-[#223452] mb-3">
                  <div className="text-[10px] text-[#6b7c96] mb-1 uppercase font-bold">Canonical Flow Path:</div>
                  <div className="flex items-center flex-wrap gap-1 text-[11px]">
                    <span className="bg-[#090d16] px-2 py-0.5 rounded text-[#00d2ff] border border-[#223452]">login</span>
                    <ArrowRight className="w-3 h-3 text-[#6b7c96]" />
                    <span className="bg-[#090d16] px-2 py-0.5 rounded text-[#00ff87] border border-[#223452]">getDashboardMetrics</span>
                    <ArrowRight className="w-3 h-3 text-[#6b7c96]" />
                    <span className="bg-[#090d16] px-2 py-0.5 rounded text-amber-400 border border-[#223452]">viewSecurityLogs</span>
                    <ArrowRight className="w-3 h-3 text-[#6b7c96]" />
                    <span className="bg-[#090d16] px-2 py-0.5 rounded text-[#ff4a6b] border border-[#223452]">updateSystemPolicy</span>
                  </div>
                </div>

                <div className="space-y-1.5 max-h-40 overflow-y-auto">
                  {rules.map((rule) => (
                    <div
                      key={rule.id}
                      className="flex items-center justify-between p-2 rounded bg-[#131c2e] border border-[#1e293b]"
                    >
                      <div className="flex items-center gap-1.5 text-[11px]">
                        <span className="text-[#00d2ff]">{rule.current_function}</span>
                        <ArrowRight className="w-3 h-3 text-[#6b7c96]" />
                        <span className="text-[#00ff87]">{rule.allowed_next_function}</span>
                      </div>
                      <button
                        onClick={() => onDeleteRule(rule.id)}
                        className="text-[#6b7c96] hover:text-[#ff4a6b] p-1 transition-colors"
                        title="Delete rule"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Add New Rule Form */}
              <form onSubmit={handleCreateRule} className="mt-3 pt-3 border-t border-[#1e293b] flex gap-2">
                <input
                  type="text"
                  placeholder="Current function"
                  value={currentFunc}
                  onChange={(e) => setCurrentFunc(e.target.value)}
                  className="flex-1 p-1.5 bg-[#131c2e] border border-[#334e78] rounded text-white text-[10px] focus:outline-none focus:border-[#00d2ff]"
                />
                <input
                  type="text"
                  placeholder="Allowed next"
                  value={nextFunc}
                  onChange={(e) => setNextFunc(e.target.value)}
                  className="flex-1 p-1.5 bg-[#131c2e] border border-[#334e78] rounded text-white text-[10px] focus:outline-none focus:border-[#00d2ff]"
                />
                <button
                  type="submit"
                  disabled={isAdding || !currentFunc || !nextFunc}
                  className="px-2.5 py-1 bg-[#00d2ff] text-black font-bold text-[10px] rounded hover:bg-white transition-colors disabled:opacity-50 flex items-center gap-1"
                >
                  <Plus className="w-3 h-3" />
                  <span>Add</span>
                </button>
              </form>
            </div>

            {/* Table: users */}
            <div className="bg-[#090d16] border border-[#223452] p-4 rounded-md">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-white font-bold uppercase text-[11px] flex items-center gap-1.5">
                  <Users className="w-3.5 h-3.5 text-[#00d2ff]" />
                  TABLE: users (Authentication Context)
                </h4>
                <span className="text-[10px] text-[#6b7c96]">{users.length} Users Seeded</span>
              </div>

              <div className="overflow-x-auto rounded border border-[#1e293b]">
                <table className="w-full text-left text-[11px]">
                  <thead className="bg-[#131c2e] text-[#6b7c96] uppercase text-[9px]">
                    <tr className="border-b border-[#1e293b]">
                      <th className="p-2">ID</th>
                      <th className="p-2">Username</th>
                      <th className="p-2">Role</th>
                      <th className="p-2">Base Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e293b]">
                    {users.map((u) => (
                      <tr key={u.id} className="hover:bg-[#131c2e]/50">
                        <td className="p-2 text-[#6b7c96]">{u.id}</td>
                        <td className="p-2 font-bold text-white">{u.username}</td>
                        <td className="p-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                              u.role === 'Admin'
                                ? 'bg-purple-500/20 text-purple-400'
                                : u.role === 'Developer'
                                ? 'bg-[#00d2ff]/20 text-[#00d2ff]'
                                : 'bg-slate-700 text-slate-300'
                            }`}
                          >
                            {u.role}
                          </span>
                        </td>
                        <td className="p-2 font-bold">
                          <span
                            className={
                              u.base_risk_score >= 70
                                ? 'text-[#ff4a6b]'
                                : u.base_risk_score > 20
                                ? 'text-amber-400'
                                : 'text-[#00ff87]'
                            }
                          >
                            {u.base_risk_score}%
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="mt-3 p-2 bg-[#131c2e]/60 rounded border border-[#1e293b] text-[10px] text-[#94a3b8] flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <span>
                  Notice how <strong>threat_actor</strong> has a base risk of 70%. When jumping out of order, the +40% penalty yields 110% (capped at 100%), immediately triggering the 75% cutoff firewall!
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-3 border-t border-[#1e293b] bg-[#131c2e] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-[#00d2ff] hover:bg-white text-black font-bold text-xs uppercase rounded transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
