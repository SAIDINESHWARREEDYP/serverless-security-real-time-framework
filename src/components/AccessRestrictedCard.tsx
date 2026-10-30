import React from 'react';
import { ShieldAlert, Lock, ArrowRight, UserCheck, Shield } from 'lucide-react';
import { AuthSession } from '../types.ts';

interface AccessRestrictedCardProps {
  requiredRole: 'Admin' | 'Developer';
  currentSession: AuthSession | null;
  onNavigateToPermitted: () => void;
  onReauthenticate?: () => void;
}

export const AccessRestrictedCard: React.FC<AccessRestrictedCardProps> = ({
  requiredRole,
  currentSession,
  onNavigateToPermitted,
  onReauthenticate
}) => {
  return (
    <div className="max-w-2xl mx-auto my-12 p-8 rounded-xl border border-rose-500/40 bg-slate-900/90 shadow-2xl backdrop-blur-md text-center space-y-5 font-mono">
      <div className="inline-flex p-4 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 mb-2">
        <ShieldAlert className="w-10 h-10" />
      </div>

      <div className="space-y-2">
        <div className="text-[11px] uppercase tracking-widest text-rose-400 font-bold">
          Zero-Trust Boundary Enforcement • HTTP 403 Forbidden
        </div>
        <h2 className="text-xl font-bold text-white font-sans">
          Access Restricted by Role Policy
        </h2>
        <p className="text-xs text-slate-300 font-sans max-w-md mx-auto">
          This management interface is restricted to principals with{' '}
          <strong className="text-white font-mono">{requiredRole}</strong> role clearance.
        </p>
      </div>

      <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-left space-y-2">
        <div className="flex items-center justify-between text-slate-400">
          <span>Active Principal Identity:</span>
          <span className="text-white font-bold">{currentSession?.user.username || 'Anonymous'}</span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span>Assigned Principal Role:</span>
          <span className="text-amber-400 font-bold">{currentSession?.user.role || 'Unauthenticated'}</span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span>Required Clearance:</span>
          <span className="text-rose-400 font-bold">{requiredRole} (Tier 3 Privileged)</span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span>Interception Point:</span>
          <span className="text-slate-300">Cloudflare Edge Interceptor RBAC Guard</span>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
        <button
          type="button"
          onClick={onNavigateToPermitted}
          className="w-full sm:w-auto px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition-colors font-sans shadow-md"
        >
          <Shield className="w-4 h-4" />
          <span>Return to Permitted Workspace</span>
        </button>

        {onReauthenticate && (
          <button
            type="button"
            onClick={onReauthenticate}
            className="w-full sm:w-auto px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition-colors font-sans shadow-md cursor-pointer"
          >
            <Lock className="w-4 h-4" />
            <span>Sign In with Privileged Credentials</span>
          </button>
        )}
      </div>
    </div>
  );
};
