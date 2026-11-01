import React, { useState } from 'react';
import {
  Sliders,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Zap,
  Save,
  RotateCcw,
  Check,
  X,
  AlertTriangle,
  HardDrive,
  Clock
} from 'lucide-react';
import { SecurityPolicyConfig } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';

interface SystemConfigSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  policyConfig: SecurityPolicyConfig;
  onUpdatePolicy: (newConfig: Partial<SecurityPolicyConfig>) => Promise<void>;
  onResetPolicy: () => Promise<void>;
  isInline?: boolean;
}

export const SystemConfigSettingsModal: React.FC<SystemConfigSettingsModalProps> = ({
  isOpen,
  onClose,
  policyConfig,
  onUpdatePolicy,
  onResetPolicy,
  isInline = false
}) => {
  const { isLight } = useTheme();
  const [maxRiskThreshold, setMaxRiskThreshold] = useState<number>(policyConfig.maxRiskThreshold ?? 75);
  const [sequenceViolationPenalty, setSequenceViolationPenalty] = useState<number>(policyConfig.sequenceViolationPenalty ?? 40);
  const [enforceStrictSequence, setEnforceStrictSequence] = useState<boolean>(policyConfig.enforceStrictSequence ?? true);
  const [globalLockdown, setGlobalLockdown] = useState<boolean>(policyConfig.globalLockdown ?? false);
  const [isSaving, setIsSaving] = useState(false);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setSuccessNotice(null);
    try {
      await onUpdatePolicy({
        maxRiskThreshold,
        sequenceViolationPenalty,
        enforceStrictSequence,
        globalLockdown
      });
      setSuccessNotice('Security configuration successfully updated and propagated across edge mesh.');
      setTimeout(() => setSuccessNotice(null), 3000);
    } catch {
      // ignore
    } finally {
      setIsSaving(false);
    }
  };

  const handleReset = async () => {
    setMaxRiskThreshold(75);
    setSequenceViolationPenalty(40);
    setEnforceStrictSequence(true);
    setGlobalLockdown(false);
    await onResetPolicy();
    setSuccessNotice('Configuration reset to Zero-Trust security baseline.');
    setTimeout(() => setSuccessNotice(null), 3000);
  };

  const content = (
    <div
      className={`relative w-full ${isInline ? 'max-w-none' : 'max-w-3xl'} rounded-3xl border shadow-2xl overflow-hidden z-10 flex flex-col font-mono transition-all ${
        isLight
          ? 'bg-white border-slate-200 text-slate-800'
          : 'bg-[#0a0f1d] border-slate-800/90 text-slate-100'
      }`}
      role={isInline ? 'region' : 'dialog'}
      aria-modal={!isInline}
      aria-label="Security Configuration and Settings"
    >
        {/* Header */}
        <div className={`p-5 sm:p-6 border-b flex items-center justify-between shrink-0 ${
          isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#0d1527] border-slate-800'
        }`}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-500 shadow-xs">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold tracking-tight">
                Security Policy &amp; Engine Settings
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Runtime parameters governing risk cutoffs, Markov state penalties, and fail-closed controls
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className={`p-2 rounded-xl border transition-all ${
              isLight ? 'bg-white hover:bg-slate-100 border-slate-200' : 'bg-slate-900 hover:bg-slate-800 border-slate-800'
            }`}
          >
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        {successNotice && (
          <div className="px-5 py-3 bg-emerald-500/15 border-b border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
            <Check className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successNotice}</span>
          </div>
        )}

        <form onSubmit={handleSave} className="p-5 sm:p-6 space-y-5 overflow-y-auto flex-1 text-xs">
          {/* Setting 1: Max Risk Threshold */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-bold text-slate-200 text-sm block">Max Risk Cutoff Threshold ($T_{`{max}`}$)</span>
                <span className="text-[11px] text-slate-400">Invocations exceeding this composite risk score are blocked immediately.</span>
              </div>
              <span className={`text-base font-bold px-3 py-1 rounded-xl border font-mono ${
                maxRiskThreshold <= 60 ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' : 'bg-amber-500/20 text-amber-400 border-amber-500/40'
              }`}>
                {maxRiskThreshold}%
              </span>
            </div>
            <input
              type="range"
              min={25}
              max={95}
              step={5}
              value={maxRiskThreshold}
              onChange={(e) => setMaxRiskThreshold(Number(e.target.value))}
              className="w-full accent-blue-500 cursor-pointer"
            />
          </div>

          {/* Setting 2: Sequence Violation Penalty */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-bold text-slate-200 text-sm block">Markov Sequence Drift Penalty ($P_{`{seq}`}$)</span>
                <span className="text-[11px] text-slate-400">Penalty added when an unexpected lateral jump occurs in the state transition graph.</span>
              </div>
              <span className="text-base font-bold px-3 py-1 rounded-xl bg-purple-500/20 text-purple-400 border border-purple-500/40 font-mono">
                +{sequenceViolationPenalty}%
              </span>
            </div>
            <input
              type="range"
              min={10}
              max={60}
              step={5}
              value={sequenceViolationPenalty}
              onChange={(e) => setSequenceViolationPenalty(Number(e.target.value))}
              className="w-full accent-purple-500 cursor-pointer"
            />
          </div>

          {/* Setting 3: Strict Sequence Enforcement Toggle */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 flex items-center justify-between gap-4">
            <div>
              <span className="font-bold text-slate-200 text-sm block">Strict Markov Transition Enforcement</span>
              <span className="text-[11px] text-slate-400">Immediately flags and rejects out-of-order function invocations.</span>
            </div>
            <button
              type="button"
              onClick={() => setEnforceStrictSequence(!enforceStrictSequence)}
              className={`w-12 h-6 rounded-full transition-colors relative cursor-pointer ${
                enforceStrictSequence ? 'bg-blue-600' : 'bg-slate-800'
              }`}
            >
              <span className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-transform ${
                enforceStrictSequence ? 'right-1' : 'left-1'
              }`} />
            </button>
          </div>

          {/* Setting 4: Emergency Perimeter Lockdown */}
          <div className="p-4 rounded-xl border border-rose-900/40 bg-rose-950/15 flex items-center justify-between gap-4">
            <div>
              <span className="font-bold text-rose-300 text-sm block flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-500" />
                Emergency Perimeter Lockdown (Kill-Switch)
              </span>
              <span className="text-[11px] text-slate-400">Restricts all non-administrator invocations and enforces +50% global threat penalty.</span>
            </div>
            <button
              type="button"
              onClick={() => setGlobalLockdown(!globalLockdown)}
              className={`w-12 h-6 rounded-full transition-colors relative cursor-pointer ${
                globalLockdown ? 'bg-rose-600' : 'bg-slate-800'
              }`}
            >
              <span className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-transform ${
                globalLockdown ? 'right-1' : 'left-1'
              }`} />
            </button>
          </div>

          {/* Setting 5: Fail-Closed Architecture Status (Read-Only Guaranteed) */}
          <div className="p-4 rounded-xl border border-emerald-900/40 bg-emerald-950/10 flex items-center justify-between gap-4">
            <div>
              <span className="font-bold text-emerald-300 text-sm block flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Fail-Closed Architecture (Inviolable Invariant)
              </span>
              <span className="text-[11px] text-slate-400">Any unhandled exception forces 100% Critical Risk and immediate 403 Forbidden.</span>
            </div>
            <span className="text-[10px] font-bold px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
              ACTIVE ENFORCED
            </span>
          </div>

          <div className="pt-2 flex items-center justify-between border-t border-slate-800">
            <button
              type="button"
              onClick={handleReset}
              className="text-slate-400 hover:text-white flex items-center gap-1.5 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Zero-Trust Defaults</span>
            </button>

            <button
              type="submit"
              disabled={isSaving}
              className="px-5 py-2.5 rounded-xl text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-2 shadow-sm transition-all disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{isSaving ? 'Saving...' : 'Save Configuration'}</span>
            </button>
          </div>
        </form>
      </div>
  );

  if (isInline) {
    return content;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 overflow-y-auto font-mono">
      <div
        className="fixed inset-0 bg-slate-950/80 backdrop-blur-md transition-opacity duration-300"
        onClick={onClose}
        aria-hidden="true"
      />
      {content}
    </div>
  );
};
