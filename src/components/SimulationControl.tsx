import React, { useState } from 'react';
import { getAuthRequestHeaders } from '../utils/authTokenStore.ts';
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
  Timer,
  Lock
} from 'lucide-react';
import { TerminalLogEntry, User, AuthSession, SecurityPolicyConfig } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';

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
  const { isLight } = useTheme();
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
          headers: getAuthRequestHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ username: 'cloud_dev' })
        });
        await onFire('cloud_dev', 'getDashboardMetrics');
      } else if (scenarioType === 'fail_closed') {
        // Fail-Closed Exception Guarantee: triggers pipeline fault, verified 100% block
        onSelectUser('secops_admin');
        setIsCustom(false);
        await fetch('/api/security/fail-closed-drill', {
          method: 'POST',
          headers: getAuthRequestHeaders({ 'Content-Type': 'application/json' }),
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
    <div className={`border p-5 rounded-2xl flex flex-col h-full font-mono shadow-sm ${
      isLight ? 'bg-white border-slate-200 text-slate-900' : 'bg-[#0f172a] border-slate-800 text-slate-100'
    }`}>
      <div className={`border-b pb-3 mb-4 flex items-center justify-between ${isLight ? 'border-slate-200' : 'border-slate-800'}`}>
        <h3 className={`text-sm font-bold uppercase tracking-wider flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
          <Terminal className={`w-4 h-4 ${isLight ? 'text-sky-600' : 'text-[#00d2ff]'}`} />
          Zero-Trust Simulation Console
        </h3>
        {currentSession?.user.role === 'Admin' ? (
          <button
            type="button"
            onClick={() => setShowTuning(!showTuning)}
            className={`text-[10px] px-2.5 py-1 rounded-lg border transition-all flex items-center gap-1.5 ${
              showTuning
                ? (isLight ? 'bg-sky-600 text-white font-bold border-sky-600' : 'bg-[#00d2ff] text-black font-bold border-[#00d2ff]')
                : (isLight ? 'bg-sky-50 text-sky-700 border-sky-200 hover:bg-sky-100' : 'bg-[#00d2ff]/10 text-[#00d2ff] border-[#00d2ff]/30 hover:bg-[#00d2ff]/20')
            }`}
          >
            <Sliders className="w-3 h-3" />
            {showTuning ? 'Hide Policy Sliders' : 'Tune Defense Rules'}
          </button>
        ) : (
          <span className={`text-[10px] px-2 py-0.5 rounded border flex items-center gap-1 ${
            isLight ? 'bg-slate-100 text-slate-600 border-slate-200' : 'bg-slate-800 text-slate-400 border-slate-700'
          }`}>
            <Lock className="w-2.5 h-2.5" />
            Policy Tuning: Admin Only
          </span>
        )}
      </div>

      {/* Defense Policy Tuning Drawer - Admin Only */}
      {showTuning && currentSession?.user.role === 'Admin' && (
        <div className={`mb-4 p-3.5 border rounded-xl space-y-3 ${
          isLight ? 'bg-slate-50 border-sky-200' : 'bg-[#090d16] border-[#00d2ff]/30'
        }`}>
          <div className={`flex items-center justify-between text-xs font-bold border-b pb-1.5 ${
            isLight ? 'text-sky-700 border-slate-200' : 'text-[#00d2ff] border-slate-800'
          }`}>
            <span className="flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              Dynamic Security Defense Parameter Tuning
            </span>
            <span className="text-[10px] text-slate-500">Live Edge Enforced</span>
          </div>

          <div>
            <div className={`flex items-center justify-between text-xs mb-1 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              <span>Firewall Cutoff Threshold:</span>
              <strong className={`font-mono tabular-nums ${isLight ? 'text-slate-900' : 'text-white'}`}>{thresholdSlider}%</strong>
            </div>
            <input
              type="range"
              min="30"
              max="95"
              step="5"
              value={thresholdSlider}
              onChange={(e) => setThresholdSlider(parseInt(e.target.value, 10))}
              className={`w-full cursor-pointer ${isLight ? 'accent-sky-600' : 'accent-[#00d2ff]'}`}
            />
            <div className="flex justify-between text-[9px] text-slate-500">
              <span>30% (Ultra Strict)</span>
              <span>75% (Default Baseline)</span>
              <span>95% (Permissive)</span>
            </div>
          </div>

          <div>
            <div className={`flex items-center justify-between text-xs mb-1 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              <span>Sequence Violation Penalty:</span>
              <strong className={`font-mono tabular-nums ${isLight ? 'text-amber-700' : 'text-amber-400'}`}>+{penaltySlider}%</strong>
            </div>
            <input
              type="range"
              min="0"
              max="70"
              step="5"
              value={penaltySlider}
              onChange={(e) => setPenaltySlider(parseInt(e.target.value, 10))}
              className="w-full accent-amber-500 cursor-pointer"
            />
          </div>

          <div className="flex items-center justify-between pt-1">
            <label className={`text-xs flex items-center gap-2 cursor-pointer ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
              <input
                type="checkbox"
                checked={strictSequence}
                onChange={(e) => setStrictSequence(e.target.checked)}
                className={`rounded ${isLight ? 'accent-sky-600' : 'accent-[#00d2ff]'}`}
              />
              <span>Enforce Strict Markov Sequential Transitions</span>
            </label>
            <button
              type="button"
              onClick={handleApplyTuning}
              className={`px-3 py-1 text-xs font-bold rounded-lg transition-colors ${
                isLight ? 'bg-sky-600 hover:bg-sky-700 text-white' : 'bg-[#00d2ff] hover:bg-white text-black'
              }`}
            >
              Update Policy
            </button>
          </div>
        </div>
      )}

      {/* 1-Click Viva Demonstration Scenarios */}
      <div className="mb-4">
        <label className="text-[10px] text-slate-500 mb-1.5 uppercase font-bold tracking-wider flex items-center justify-between">
          <span>1-Click Viva Demonstration Scenarios</span>
          <span className={`text-[9px] ${isLight ? 'text-emerald-700' : 'text-[#00ff87]'}`}>Automated Test Engine</span>
        </label>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('admin_path')}
            className={`p-2 text-left rounded-lg border transition-all flex items-center justify-between group disabled:opacity-50 ${
              isLight
                ? 'bg-slate-50 hover:bg-emerald-50 border-slate-200 text-slate-600 hover:text-emerald-800'
                : 'bg-[#090d16] hover:bg-slate-800/80 border-slate-800 text-slate-400 hover:text-[#00ff87]'
            }`}
          >
            <div>
              <div className={`font-bold flex items-center gap-1.5 ${isLight ? 'text-slate-900 group-hover:text-emerald-700' : 'text-white group-hover:text-[#00ff87]'}`}>
                <CheckCircle2 className={`w-3 h-3 ${isLight ? 'text-emerald-600' : 'text-[#00ff87]'}`} />
                Admin Golden Path
              </div>
              <div className="text-[10px] text-slate-500">Multi-step sequence (0% risk)</div>
            </div>
            <FastForward className={`w-3 h-3 shrink-0 ${isLight ? 'text-emerald-600' : 'text-[#00ff87]'}`} />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('rbac_breach')}
            className={`p-2 text-left rounded-lg border transition-all flex items-center justify-between group disabled:opacity-50 ${
              isLight
                ? 'bg-slate-50 hover:bg-rose-50 border-slate-200 text-slate-600 hover:text-rose-800'
                : 'bg-[#090d16] hover:bg-slate-800/80 border-slate-800 text-slate-400 hover:text-[#ff4a6b]'
            }`}
          >
            <div>
              <div className={`font-bold flex items-center gap-1.5 ${isLight ? 'text-slate-900 group-hover:text-rose-700' : 'text-white group-hover:text-[#ff4a6b]'}`}>
                <ShieldAlert className={`w-3 h-3 ${isLight ? 'text-rose-600' : 'text-[#ff4a6b]'}`} />
                Privilege Escalation
              </div>
              <div className="text-[10px] text-slate-500">Guest calls KMS Keys (RBAC 90%)</div>
            </div>
            <ShieldAlert className={`w-3 h-3 shrink-0 ${isLight ? 'text-rose-600' : 'text-[#ff4a6b]'}`} />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('sequence_anomaly')}
            className={`p-2 text-left rounded-lg border transition-all flex items-center justify-between group disabled:opacity-50 ${
              isLight
                ? 'bg-slate-50 hover:bg-amber-50 border-slate-200 text-slate-600 hover:text-amber-800'
                : 'bg-[#090d16] hover:bg-slate-800/80 border-slate-800 text-slate-400 hover:text-amber-400'
            }`}
          >
            <div>
              <div className={`font-bold flex items-center gap-1.5 ${isLight ? 'text-slate-900 group-hover:text-amber-800' : 'text-white group-hover:text-amber-400'}`}>
                <AlertTriangle className="w-3 h-3 text-amber-500" />
                Sequence Bypass
              </div>
              <div className="text-[10px] text-slate-500">Dev skips metrics (+40% penalty)</div>
            </div>
            <Layers className="w-3 h-3 text-amber-500 shrink-0" />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('high_risk_exploit')}
            className={`p-2 text-left rounded-lg border transition-all flex items-center justify-between group disabled:opacity-50 ${
              isLight
                ? 'bg-rose-50/70 hover:bg-rose-100 border-rose-200 text-rose-800'
                : 'bg-[#1c0f14] hover:bg-[#2a131b] border-red-900/60 text-slate-400 hover:text-red-400'
            }`}
          >
            <div>
              <div className={`font-bold flex items-center gap-1.5 ${isLight ? 'text-rose-900' : 'text-red-200 group-hover:text-red-400'}`}>
                <Flame className={`w-3 h-3 ${isLight ? 'text-rose-600' : 'text-red-400'}`} />
                Malicious Infiltration
              </div>
              <div className={`text-[10px] ${isLight ? 'text-rose-700' : 'text-red-400/70'}`}>70% base risk cutoff (&gt;=75%)</div>
            </div>
            <ShieldAlert className={`w-3 h-3 shrink-0 ${isLight ? 'text-rose-600' : 'text-red-400'}`} />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('rate_limit')}
            className={`p-2 text-left rounded-lg border transition-all flex items-center justify-between group disabled:opacity-50 ${
              isLight
                ? 'bg-amber-50/70 hover:bg-amber-100 border-amber-200 text-amber-900'
                : 'bg-[#17120a] hover:bg-[#251b0d] border-amber-800/60 text-slate-400 hover:text-amber-300'
            }`}
          >
            <div>
              <div className={`font-bold flex items-center gap-1.5 ${isLight ? 'text-amber-900' : 'text-amber-200 group-hover:text-amber-300'}`}>
                <Activity className="w-3 h-3 text-amber-500" />
                Rate Limiting (+20%)
              </div>
              <div className={`text-[10px] ${isLight ? 'text-amber-800' : 'text-amber-400/70'}`}>&gt;10 req/min (ABNORMAL_REQUEST_RATE)</div>
            </div>
            <Timer className="w-3 h-3 text-amber-500 shrink-0" />
          </button>

          <button
            type="button"
            disabled={isFiring || isRunningScenario}
            onClick={() => executeScenario('fail_closed')}
            className={`p-2 text-left rounded-lg border transition-all flex items-center justify-between group disabled:opacity-50 ${
              isLight
                ? 'bg-rose-50/70 hover:bg-rose-100 border-rose-200 text-rose-900'
                : 'bg-[#1f0e13] hover:bg-[#2e121a] border-rose-800/70 text-slate-400 hover:text-rose-300'
            }`}
          >
            <div>
              <div className={`font-bold flex items-center gap-1.5 ${isLight ? 'text-rose-900' : 'text-rose-200 group-hover:text-rose-300'}`}>
                <AlertOctagon className={`w-3 h-3 ${isLight ? 'text-rose-600' : 'text-rose-400'}`} />
                Fail-Closed Guarantee
              </div>
              <div className={`text-[10px] ${isLight ? 'text-rose-700' : 'text-rose-400/70'}`}>Pipeline fault =&gt; 100% Critical Block</div>
            </div>
            <AlertOctagon className={`w-3 h-3 shrink-0 ${isLight ? 'text-rose-600' : 'text-rose-400'}`} />
          </button>
        </div>
      </div>

      {/* Select User */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-1.5">
          <label htmlFor="user" className="block text-[11px] text-slate-500 uppercase font-bold tracking-wider">
            Simulate Principal Identity
          </label>
          {currentSession && selectedUser !== currentSession.user.username && (
            <button
              type="button"
              onClick={() => onSelectUser(currentSession.user.username)}
              className={`text-[10px] hover:underline ${isLight ? 'text-emerald-700' : 'text-[#00ff87]'}`}
            >
              Use Logged-in ({currentSession.user.username})
            </button>
          )}
        </div>
        <select
          id="user"
          value={selectedUser}
          onChange={(e) => onSelectUser(e.target.value)}
          className={`w-full p-2.5 border text-xs rounded-lg focus:outline-none transition-colors ${
            isLight
              ? 'bg-white border-slate-300 text-slate-900 focus:border-sky-600'
              : 'bg-[#090d16] border-slate-700 text-white focus:border-[#00d2ff]'
          }`}
        >
          {users.map(u => (
            <option key={u.id} value={u.username}>
              {u.username} [Role: {u.role} | Base Risk: {u.base_risk_score}%]
            </option>
          ))}
        </select>

        {currentUserObj && (
          <div className={`mt-1.5 flex items-center justify-between text-[11px] px-2.5 py-1.5 rounded-lg border tabular-nums ${
            isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#090d16]/70 border-slate-800'
          }`}>
            <span className="text-slate-500">Role Clearance: <strong className={isLight ? 'text-slate-900' : 'text-white'}>{currentUserObj.role}</strong></span>
            <span className="text-slate-500">Base Risk: <strong className={
              currentUserObj.base_risk_score >= 70
                ? (isLight ? 'text-rose-700' : 'text-[#ff4a6b]')
                : currentUserObj.base_risk_score > 20
                ? (isLight ? 'text-amber-700' : 'text-amber-400')
                : (isLight ? 'text-emerald-700' : 'text-[#00ff87]')
            }>{currentUserObj.base_risk_score}%</strong></span>
          </div>
        )}
      </div>

      {/* Select Route */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-1.5">
          <label htmlFor="route" className="block text-[11px] text-slate-500 uppercase font-bold tracking-wider">
            Target Serverless Cloud Function
          </label>
          <div className="flex items-center gap-2">
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono border ${
              currentSession?.user.role === 'Admin'
                ? (isLight ? 'bg-purple-50 text-purple-800 border-purple-200' : 'bg-purple-950 text-purple-300 border-purple-800')
                : currentSession?.user.role === 'Developer'
                ? (isLight ? 'bg-blue-50 text-blue-800 border-blue-200' : 'bg-blue-950 text-blue-300 border-blue-800')
                : (isLight ? 'bg-emerald-50 text-emerald-800 border-emerald-200' : 'bg-emerald-950 text-emerald-300 border-emerald-800')
            }`}>
              {currentSession?.user.role === 'Admin' ? 'Tier 1, 2, 3 Permitted' :
               currentSession?.user.role === 'Developer' ? 'Tier 1 & 2 Permitted' :
               'Tier 1 Only'}
            </span>
            <button
              type="button"
              onClick={() => setIsCustom(!isCustom)}
              className={`text-[10px] hover:underline ${isLight ? 'text-sky-700' : 'text-[#00d2ff]'}`}
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
            className={`w-full p-2.5 border text-xs rounded-lg focus:outline-none transition-colors ${
              isLight
                ? 'bg-white border-slate-300 text-slate-900 focus:border-sky-600'
                : 'bg-[#090d16] border-slate-700 text-white focus:border-[#00d2ff]'
            }`}
          >
            <option value="getDashboardMetrics">
              /api/getDashboardMetrics [Tier 1 · Telemetry - Permitted for {currentSession?.user.role || 'All'}]
            </option>
            <option value="viewSecurityLogs">
              /api/viewSecurityLogs [Tier 2 · Audit Logs - {currentSession?.user.role === 'Guest' ? '403 Forbidden for Guest' : 'Permitted'}]
            </option>
            <option value="deployWorkerCode">
              /api/deployWorkerCode [Tier 2 · Deploy Worker - {currentSession?.user.role === 'Guest' ? '403 Forbidden for Guest' : 'Permitted'}]
            </option>
            <option value="rotateEncryptionKeys">
              /api/rotateEncryptionKeys [Tier 3 · KMS Master - {currentSession?.user.role === 'Admin' ? 'Permitted' : '403 Forbidden (Admin Only)'}]
            </option>
            <option value="updateSystemPolicy">
              /api/updateSystemPolicy [Tier 3 · Defense Policy - {currentSession?.user.role === 'Admin' ? 'Permitted' : '403 Forbidden (Admin Only)'}]
            </option>
            <option value="purgeColdStorageBackups">
              /api/purgeColdStorageBackups [Tier 3 · Archive Purge - {currentSession?.user.role === 'Admin' ? 'Permitted' : '403 Forbidden (Admin Only)'}]
            </option>
          </select>
        ) : (
          <div className="relative">
            <span className="absolute left-3 top-2.5 text-slate-500 text-xs">/api/</span>
            <input
              type="text"
              value={customRoute}
              onChange={(e) => setCustomRoute(e.target.value)}
              placeholder="e.g. overrideSystemAccess"
              className={`w-full pl-12 pr-3 py-2.5 border text-xs rounded-lg focus:outline-none ${
                isLight
                  ? 'bg-white border-slate-300 text-slate-900 focus:border-sky-600'
                  : 'bg-[#090d16] border-slate-700 text-white focus:border-[#00d2ff]'
              }`}
            />
          </div>
        )}
      </div>

      {/* Fire Interceptor Button */}
      <button
        id="btn-fire-pipeline"
        onClick={handleFire}
        disabled={isFiring || isRunningScenario}
        className={`w-full py-3 font-bold text-xs uppercase tracking-wider rounded-xl transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-sm ${
          isLight
            ? 'bg-sky-600 hover:bg-sky-700 text-white'
            : 'bg-[#00d2ff] hover:bg-white text-black shadow-[0_0_15px_rgba(0,210,255,0.25)]'
        }`}
      >
        <Play className={`w-3.5 h-3.5 fill-current ${isFiring || isRunningScenario ? 'animate-spin' : ''}`} />
        <span>{isFiring || isRunningScenario ? 'Evaluating Security Pipeline...' : 'Fire Pipeline Interceptor'}</span>
      </button>

      {/* Terminal Output */}
      <div className="mt-4 flex flex-col flex-1 min-h-[220px]">
        <div className="flex items-center justify-between pb-1 text-[11px] text-slate-500">
          <span className="flex items-center gap-1.5">
            <span className={`inline-block w-2 h-2 rounded-full ${isLight ? 'bg-sky-600' : 'bg-[#00d2ff]'}`}></span>
            Interceptor Telemetry Console
          </span>
          {terminalLogs.length > 0 && (
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyLogs}
                className={`flex items-center gap-1 transition-colors ${isLight ? 'hover:text-slate-900' : 'hover:text-white'}`}
                title="Copy Terminal Logs"
              >
                {copied ? <Check className={`w-3 h-3 ${isLight ? 'text-emerald-600' : 'text-[#00ff87]'}`} /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
              <button
                onClick={onClearTerminal}
                className={`transition-colors ${isLight ? 'hover:text-rose-700' : 'hover:text-[#ff4a6b]'}`}
              >
                Clear
              </button>
            </div>
          )}
        </div>

        <div
          id="terminalOutput"
          className={`p-3 rounded-xl border text-[11px] leading-relaxed overflow-y-auto max-h-[260px] flex-1 flex flex-col gap-1 ${
            isLight ? 'bg-slate-50 border-slate-300' : 'bg-[#02060c] border-slate-800'
          }`}
        >
          {terminalLogs.length === 0 ? (
            <div className="text-slate-500 text-center my-auto py-6">
              Simulation telemetry dormant. Select parameters and fire the pipeline or trigger a Viva Scenario.
            </div>
          ) : (
            terminalLogs.map((log) => {
              let colorClass = isLight ? 'text-slate-700' : 'text-[#cbd5e1]';
              if (log.type === 'info') colorClass = isLight ? 'text-sky-700' : 'text-[#00d2ff]';
              if (log.type === 'post' || log.type === 'get') colorClass = isLight ? 'text-slate-600' : 'text-[#94a3b8]';
              if (log.type === 'success') colorClass = isLight ? 'text-emerald-700' : 'text-[#00ff87]';
              if (log.type === 'alert' || log.type === 'error') colorClass = isLight ? 'text-rose-700' : 'text-[#ff4a6b]';
              if (log.type === 'metric') colorClass = isLight ? 'text-amber-700' : 'text-[#f59e0b]';

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
