import React, { useState } from 'react';
import { 
  Play, 
  Terminal, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  FastForward, 
  Info, 
  Copy, 
  Check, 
  Sliders, 
  Zap, 
  ShieldCheck, 
  Layers, 
  Flame,
  Activity,
  AlertOctagon,
  Timer
} from 'lucide-react';
import { TerminalLogEntry, User, AuthSession, SecurityPolicyConfig } from '../types.ts';

interface SimulationControlProps {
  users: User[];
  selectedUser: string;
  onSelectUser: (u: string) => void;
  selectedRoute: string;
  onSelectRoute: (r: string) => void;
  onFire: (user: string, route: string) => Promise<void>;
  isFiring: boolean;
  terminalLogs: TerminalLogEntry[];
  onClearTerminal: () => void;
  currentSession: AuthSession | null;
  policyConfig: SecurityPolicyConfig;
  onUpdatePolicyConfig: (newConfig: Partial<SecurityPolicyConfig>) => Promise<void>;
}

export const SimulationControl: React.FC<SimulationControlProps> = ({
  users,
  selectedUser,
  onSelectUser,
  selectedRoute,
  onSelectRoute,
  onFire,
  isFiring,
  terminalLogs,
  onClearTerminal,
  currentSession,
  policyConfig,
  onUpdatePolicyConfig
}) => {
  const [customRoute, setCustomRoute] = useState('');
  const [isCustom, setIsCustom] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showTuning, setShowTuning] = useState(false);
  const [isRunningScenario, setIsRunningScenario] = useState(false);

  // Local copy for sliders
  const [thresholdSlider, setThresholdSlider] = useState(policyConfig.maxRiskThreshold || 75);
  const [penaltySlider, setPenaltySlider] = useState(policyConfig.sequenceViolationPenalty || 40);
  const [strictSequence, setStrictSequence] = useState(policyConfig.enforceStrictSequence ?? true);

  const currentUserObj = users.find(u => u.username === selectedUser);

  const handleFire = () => {
    const routeToFire = isCustom ? customRoute.replace(/^\/api\//, '') : selectedRoute;
    if (!routeToFire) return;
    onFire(selectedUser, routeToFire);
  };

  const handleCopyLogs = () => {
    const text = terminalLogs.map(l => l.text).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Run automated multi-step viva demonstration attack & defense scenarios
  const executeScenario = async (scenarioType: 'admin_path' | 'rbac_breach' | 'sequence_anomaly' | 'high_risk_exploit' | 'rate_limit' | 'fail_closed') => {
    if (isFiring || isRunningScenario) return;
    setIsRunningScenario(true);

    try {
      if (scenarioType === 'admin_path') {
        // Legitimate Admin Golden Flow: metrics -> logs -> deployWorkerCode
        onSelectUser('secops_admin');
        setIsCustom(false);
        onSelectRoute('getDashboardMetrics');
        await onFire('secops_admin', 'getDashboardMetrics');
        await new Promise(r => setTimeout(r, 600));
        onSelectRoute('viewSecurityLogs');
        await onFire('secops_admin', 'viewSecurityLogs');
        await new Promise(r => setTimeout(r, 600));
        onSelectRoute('deployWorkerCode');
        await onFire('secops_admin', 'deployWorkerCode');
      } else if (scenarioType === 'rbac_breach') {
        // Guest attempting high-privilege KMS rotation
        onSelectUser('auditor_guest');
        setIsCustom(false);
        onSelectRoute('rotateEncryptionKeys');
        await onFire('auditor_guest', 'rotateEncryptionKeys');
      } else if (scenarioType === 'sequence_anomaly') {
        // Dev skipping metrics and jumping directly to deployWorkerCode
        onSelectUser('cloud_dev');
        setIsCustom(false);
        onSelectRoute('deployWorkerCode');
        await onFire('cloud_dev', 'deployWorkerCode');
      } else if (scenarioType === 'high_risk_exploit') {
        // Untrusted actor attempting unverified jump
        onSelectUser('threat_actor');
        setIsCustom(false);
        onSelectRoute('viewSecurityLogs');
        await onFire('threat_actor', 'viewSecurityLogs');
      } else if (scenarioType === 'rate_limit') {
        // Dynamic rate limiting check: bursts requests > 10 req/min
        onSelectUser('cloud_dev');
        setIsCustom(false);
        await fetch('/api/security/rate-limit-drill', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'cloud_dev' })
        });
        await onFire('cloud_dev', 'getDashboardMetrics');
      } else if (scenarioType === 'fail_closed') {
        // Fail-Closed Exception Guarantee: triggers pipeline fault, verified 100% block
        onSelectUser('secops_admin');
        setIsCustom(false);
        await fetch('/api/security/fail-closed-drill', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'secops_admin', errorType: 'EDGE_POLICY_EVAL_TIMEOUT' })
        });
        await onFire('secops_admin', 'getDashboardMetrics');
      }
    } finally {
      setIsRunningScenario(false);
    }
  };

  const handleApplyTuning = async () => {
    await onUpdatePolicyConfig({
      maxRiskThreshold: thresholdSlider,
      sequenceViolationPenalty: penaltySlider,
      enforceStrictSequence: strictSequence
    });
  };

  return (
    <div className="bg-[#131c2e] border border-[#223452] p-5 rounded-md flex flex-col h-full font-mono">
      <div className="border-b border-[#223452] pb-3 mb-4 flex items-center justify-between">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[#00d2ff]" />
          Zero-Trust Simulation Console
        </h3>
        {currentSession?.user.role === 'Admin' ? (
          <button
            type="button"
            onClick={() => setShowTuning(!showTuning)}
            className={`text-[10px] px-2.5 py-1 rounded border transition-all flex items-center gap-1.5 ${
              showTuning
                ? 'bg-[#00d2ff] text-black font-bold border-[#00d2ff]'
                : 'bg-[#00d2ff]/10 text-[#00d2ff] border-[#00d2ff]/30 hover:bg-[#00d2ff]/20'
            }`}
          >
            <Sliders className="w-3 h-3" />
            {showTuning ? 'Hide Policy Sliders' : 'Tune Defense Rules'}
          </button>
        ) : (
          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1">
            <Lock className="w-2.5 h-2.5" />
            Policy Tuning: Admin Only
          </span>
        )}
      </div>

      {/* Defense Policy Tuning Drawer - Admin Only */}
      {showTuning && currentSession?.user.role === 'Admin' && (
        <div className="mb-4 p-3.5 bg-[#090d16] border border-[#00d2ff]/30 rounded-lg space-y-3">
          <div className="flex items-center justify-between text-xs text-[#00d2ff] font-bold border-b border-[#223452] pb-1.5">
            <span className="flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              Dynamic Security Defense Parameter Tuning
            </span>
            <span className="text-[10px] text-[#94a3b8]">Live Edge Enforced</span>
          </div>

          <div>
            <div className="flex items-center justify-between text-xs text-[#94a3b8] mb-1">
              <span>Firewall Cutoff Threshold:</span>
              <strong className="text-white font-mono">{thresholdSlider}%</strong>
            </div>
            <input
              type="range"
              min="30"
              max="95"
              step="5"
              value={thresholdSlider}
              onChange={(e) => setThresholdSlider(parseInt(e.target.value, 10))}
              className="w-full accent-[#00d2ff] cursor-pointer"
            />
            <div className="flex justify-between text-[9px] text-[#64748b]">
              <span>30% (Ultra Strict)</span>
              <span>75% (Default Baseline)</span>
              <span>95% (Permissive)</span>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between text-xs text-[#94a3b8] mb-1">
              <span>Sequence Violation Penalty:</span>
              <strong className="text-amber-400 font-mono">+{penaltySlider}%</strong>
            </div>
            <input
              type="range"
              min="0"
              max="70"
              step="5"
              value={penaltySlider}
              onChange={(e) => setPenaltySlider(parseInt(e.target.value, 10))}
              className="w-full accent-amber-400 cursor-pointer"
            />
          </div>

          <div className="flex items-center justify-between pt-1">
            <label className="text-xs text-[#94a3b8] flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={strictSequence}
                onChange={(e) => setStrictSequence(e.target.checked)}
                className="rounded accent-[#00d2ff]"
              />
              <span>Enforce Strict Markov Sequential Transitions</span>
            </label>
            <button
              type="button"
              onClick={handleApplyTuning}
              className="px-3 py-1 bg-[#00d2ff] hover:bg-white text-black text-xs font-bold rounded transition-colors"
            >
              Update Policy
            </button>
          </div>
        </div>
      )}

      {/* 1-Click Viva Demonstration Scenarios */}
      <div className="mb-4">
        <label className="block text-[10px] text-[#6b7c96] mb-1.5 uppercase font-bold tracking-wider flex items-center justify-between">
          <span>1-Click Viva Demonstration Scenarios</span>
          <span className="text-[#00ff87] text-[9px]">Automated Test Engine</span>
        </label>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('admin_path')}
            className="p-2 text-left rounded bg-[#090d16] hover:bg-[#1a273f] border border-[#223452] text-[#94a3b8] hover:text-[#00ff87] transition-all flex items-center justify-between group disabled:opacity-50"
          >
            <div>
              <div className="text-white font-bold group-hover:text-[#00ff87] flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3 text-[#00ff87]" />
                Admin Golden Path
              </div>
              <div className="text-[10px] text-[#64748b]">Multi-step sequence (0% risk)</div>
            </div>
            <FastForward className="w-3 h-3 text-[#00ff87] shrink-0" />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('rbac_breach')}
            className="p-2 text-left rounded bg-[#090d16] hover:bg-[#1a273f] border border-[#223452] text-[#94a3b8] hover:text-[#ff4a6b] transition-all flex items-center justify-between group disabled:opacity-50"
          >
            <div>
              <div className="text-white font-bold group-hover:text-[#ff4a6b] flex items-center gap-1.5">
                <ShieldAlert className="w-3 h-3 text-[#ff4a6b]" />
                Privilege Escalation
              </div>
              <div className="text-[10px] text-[#64748b]">Guest calls KMS Keys (RBAC 90%)</div>
            </div>
            <ShieldAlert className="w-3 h-3 text-[#ff4a6b] shrink-0" />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('sequence_anomaly')}
            className="p-2 text-left rounded bg-[#090d16] hover:bg-[#1a273f] border border-[#223452] text-[#94a3b8] hover:text-amber-400 transition-all flex items-center justify-between group disabled:opacity-50"
          >
            <div>
              <div className="text-white font-bold group-hover:text-amber-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3 h-3 text-amber-400" />
                Sequence Bypass
              </div>
              <div className="text-[10px] text-[#64748b]">Dev skips metrics (+40% penalty)</div>
            </div>
            <Layers className="w-3 h-3 text-amber-400 shrink-0" />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('high_risk_exploit')}
            className="p-2 text-left rounded bg-[#1c0f14] hover:bg-[#2a131b] border border-red-900/60 text-[#94a3b8] hover:text-red-400 transition-all flex items-center justify-between group disabled:opacity-50"
          >
            <div>
              <div className="text-red-200 font-bold group-hover:text-red-400 flex items-center gap-1.5">
                <Flame className="w-3 h-3 text-red-400" />
                Malicious Infiltration
              </div>
              <div className="text-[10px] text-red-400/70">70% base risk cutoff (&gt;=75%)</div>
            </div>
            <ShieldAlert className="w-3 h-3 text-red-400 shrink-0" />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('rate_limit')}
            className="p-2 text-left rounded bg-[#17120a] hover:bg-[#251b0d] border border-amber-800/60 text-[#94a3b8] hover:text-amber-300 transition-all flex items-center justify-between group disabled:opacity-50"
          >
            <div>
              <div className="text-amber-200 font-bold group-hover:text-amber-300 flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-amber-400" />
                Rate Limiting (+20%)
              </div>
              <div className="text-[10px] text-amber-400/70">&gt;10 req/min (ABNORMAL_REQUEST_RATE)</div>
            </div>
            <Timer className="w-3 h-3 text-amber-400 shrink-0" />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('fail_closed')}
            className="p-2 text-left rounded bg-[#1f0e13] hover:bg-[#2e121a] border border-rose-800/70 text-[#94a3b8] hover:text-rose-300 transition-all flex items-center justify-between group disabled:opacity-50"
          >
            <div>
              <div className="text-rose-200 font-bold group-hover:text-rose-300 flex items-center gap-1.5">
                <AlertOctagon className="w-3 h-3 text-rose-400" />
                Fail-Closed Guarantee
              </div>
              <div className="text-[10px] text-rose-400/70">Pipeline fault =&gt; 100% Critical Block</div>
            </div>
            <AlertOctagon className="w-3 h-3 text-rose-400 shrink-0" />
          </button>
        </div>
      </div>

      {/* Select User */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-1.5">
          <label htmlFor="user" className="block text-[11px] text-[#6b7c96] uppercase font-bold tracking-wider">
            Simulate Principal Identity
          </label>
          {currentSession && selectedUser !== currentSession.user.username && (
            <button
              type="button"
              onClick={() => onSelectUser(currentSession.user.username)}
              className="text-[10px] text-[#00ff87] hover:underline"
            >
              Use Logged-in ({currentSession.user.username})
            </button>
          )}
        </div>
        <select
          id="user"
          value={selectedUser}
          onChange={(e) => onSelectUser(e.target.value)}
          className="w-full p-2.5 bg-[#090d16] border border-[#334e78] text-white text-xs rounded focus:outline-none focus:border-[#00d2ff] transition-colors"
        >
          {users.map(u => (
            <option key={u.id} value={u.username}>
              {u.username} [Role: {u.role} | Base Risk: {u.base_risk_score}%]
            </option>
          ))}
        </select>

        {currentUserObj && (
          <div className="mt-1.5 flex items-center justify-between text-[11px] px-2 py-1 rounded bg-[#090d16]/70 border border-[#223452]">
            <span className="text-[#6b7c96]">Role Clearance: <strong className="text-white">{currentUserObj.role}</strong></span>
            <span className="text-[#6b7c96]">Base Risk: <strong className={currentUserObj.base_risk_score >= 70 ? 'text-[#ff4a6b]' : currentUserObj.base_risk_score > 20 ? 'text-amber-400' : 'text-[#00ff87]'}>{currentUserObj.base_risk_score}%</strong></span>
          </div>
        )}
      </div>

      {/* Select Route */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-1.5">
          <label htmlFor="route" className="block text-[11px] text-[#6b7c96] uppercase font-bold tracking-wider">
            Target Serverless Cloud Function
          </label>
          <div className="flex items-center gap-2">
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
              currentSession?.user.role === 'Admin' ? 'bg-purple-950 text-purple-300 border border-purple-800' :
              currentSession?.user.role === 'Developer' ? 'bg-blue-950 text-blue-300 border border-blue-800' :
              'bg-emerald-950 text-emerald-300 border border-emerald-800'
            }`}>
              {currentSession?.user.role === 'Admin' ? 'Tier 1, 2, 3 Permitted' :
               currentSession?.user.role === 'Developer' ? 'Tier 1 & 2 Permitted' :
               'Tier 1 Only'}
            </span>
            <button
              type="button"
              onClick={() => setIsCustom(!isCustom)}
              className="text-[10px] text-[#00d2ff] hover:underline"
            >
              {isCustom ? 'Standard Cloud Functions' : 'Custom Route'}
            </button>
          </div>
        </div>

        {!isCustom ? (
          <select
            id="route"
            value={selectedRoute}
            onChange={(e) => onSelectRoute(e.target.value)}
            className="w-full p-2.5 bg-[#090d16] border border-[#334e78] text-white text-xs rounded focus:outline-none focus:border-[#00d2ff] transition-colors"
          >
            <option value="getDashboardMetrics">
              /api/getDashboardMetrics [Tier 1 • Telemetry - Permitted for {currentSession?.user.role || 'All'}]
            </option>
            <option value="viewSecurityLogs">
              /api/viewSecurityLogs [Tier 2 • Audit Logs - {currentSession?.user.role === 'Guest' ? '403 Forbidden for Guest' : 'Permitted'}]
            </option>
            <option value="deployWorkerCode">
              /api/deployWorkerCode [Tier 2 • Deploy Worker - {currentSession?.user.role === 'Guest' ? '403 Forbidden for Guest' : 'Permitted'}]
            </option>
            <option value="rotateEncryptionKeys">
              /api/rotateEncryptionKeys [Tier 3 • KMS Master - {currentSession?.user.role === 'Admin' ? 'Permitted' : '403 Forbidden (Admin Only)'}]
            </option>
            <option value="updateSystemPolicy">
              /api/updateSystemPolicy [Tier 3 • Defense Policy - {currentSession?.user.role === 'Admin' ? 'Permitted' : '403 Forbidden (Admin Only)'}]
            </option>
            <option value="purgeColdStorageBackups">
              /api/purgeColdStorageBackups [Tier 3 • Archive Purge - {currentSession?.user.role === 'Admin' ? 'Permitted' : '403 Forbidden (Admin Only)'}]
            </option>
          </select>
        ) : (
          <div className="relative">
            <span className="absolute left-3 top-2.5 text-[#6b7c96] text-xs">/api/</span>
            <input
              type="text"
              value={customRoute}
              onChange={(e) => setCustomRoute(e.target.value)}
              placeholder="e.g. overrideSystemAccess"
              className="w-full pl-12 pr-3 py-2.5 bg-[#090d16] border border-[#334e78] text-white text-xs rounded focus:outline-none focus:border-[#00d2ff]"
            />
          </div>
        )}
      </div>

      {/* Fire Interceptor Button */}
      <button
        id="btn-fire-pipeline"
        onClick={handleFire}
        disabled={isFiring || isRunningScenario}
        className="w-full py-3 bg-[#00d2ff] hover:bg-white text-black font-bold text-xs uppercase tracking-wider rounded transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(0,210,255,0.25)] hover:shadow-[0_0_20px_rgba(0,210,255,0.5)] flex items-center justify-center gap-2"
      >
        <Play className={`w-3.5 h-3.5 fill-current ${isFiring || isRunningScenario ? 'animate-spin' : ''}`} />
        <span>{isFiring || isRunningScenario ? 'Evaluating Security Pipeline...' : 'Fire Pipeline Interceptor'}</span>
      </button>

      {/* Terminal Output */}
      <div className="mt-4 flex flex-col flex-1 min-h-[220px]">
        <div className="flex items-center justify-between pb-1 text-[11px] text-[#6b7c96]">
          <span className="flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-[#00d2ff]"></span>
            Interceptor Telemetry Console
          </span>
          {terminalLogs.length > 0 && (
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyLogs}
                className="hover:text-white flex items-center gap-1 transition-colors"
                title="Copy Terminal Logs"
              >
                {copied ? <Check className="w-3 h-3 text-[#00ff87]" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
              <button
                onClick={onClearTerminal}
                className="hover:text-[#ff4a6b] transition-colors"
              >
                Clear
              </button>
            </div>
          )}
        </div>

        <div
          id="terminalOutput"
          className="p-3 bg-[#02060c] border-l-2 border-[#00d2ff] rounded-r text-[11px] leading-relaxed overflow-y-auto max-h-[260px] flex-1 flex flex-col gap-1 border border-y-[#1e293b] border-r-[#1e293b]"
        >
          {terminalLogs.length === 0 ? (
            <div className="text-[#4a5d78] text-center my-auto py-6">
              Simulation telemetry dormant. Select parameters and fire the pipeline or trigger a Viva Scenario.
            </div>
          ) : (
            terminalLogs.map((log) => {
              let colorClass = 'text-[#cbd5e1]';
              if (log.type === 'info') colorClass = 'text-[#00d2ff]';
              if (log.type === 'post' || log.type === 'get') colorClass = 'text-[#94a3b8]';
              if (log.type === 'success') colorClass = 'text-[#00ff87]';
              if (log.type === 'alert' || log.type === 'error') colorClass = 'text-[#ff4a6b]';
              if (log.type === 'metric') colorClass = 'text-[#f59e0b]';

              return (
                <div key={log.id} className={`${colorClass} font-mono whitespace-pre-wrap break-all`}>
                  {log.text}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
