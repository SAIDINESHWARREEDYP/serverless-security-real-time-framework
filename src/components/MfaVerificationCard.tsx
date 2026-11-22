import React, { useState, useEffect, useRef } from 'react';
import {
  Smartphone,
  MessageSquare,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  Clock,
  RefreshCw,
  ArrowLeft,
  Copy,
  Check,
  Lock,
  Sparkles,
  Send,
  LifeBuoy,
  Key,
  Shield,
  Fingerprint,
  AlertTriangle
} from 'lucide-react';
import { MfaPendingChallenge, AuthSession, User } from '../types.ts';
import {
  getTotpRemainingSeconds
} from '../utils/mfa.ts';
import { MfaEnrollmentPanel, MfaEnrollmentPayload } from './MfaEnrollmentPanel.tsx';

interface MfaVerificationCardProps {
  challenge: MfaPendingChallenge;
  onVerifySuccess: (session: AuthSession) => void;
  onCancel: () => void;
  onAddTerminalLog?: (type: 'info' | 'post' | 'get' | 'success' | 'alert' | 'error' | 'metric', text: string) => void;
  variant?: 'page' | 'modal';
}

export const MfaVerificationCard: React.FC<MfaVerificationCardProps> = ({
  challenge,
  onVerifySuccess,
  onCancel,
  onAddTerminalLog,
  variant = 'page'
}) => {
  const [method, setMethod] = useState<'authenticator' | 'sms' | 'backup_code'>('authenticator');
  const [digits, setDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [recoveryCodeInput, setRecoveryCodeInput] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [attemptsLeft, setAttemptsLeft] = useState<number>(challenge.attemptsLeft ?? 5);
  const [copiedCode, setCopiedCode] = useState(false);
  const [resendCooldown, setResendCooldown] = useState<number>(0);
  const [enrollmentData, setEnrollmentData] = useState<MfaEnrollmentPayload | null>(null);
  const [enrollmentLoading, setEnrollmentLoading] = useState(false);
  const [enrollmentError, setEnrollmentError] = useState<string | null>(null);

  // Keep attemptsLeft synchronized with backend challenge state
  useEffect(() => {
    if (challenge.attemptsLeft !== undefined) {
      setAttemptsLeft(challenge.attemptsLeft);
    }
  }, [challenge.attemptsLeft]);

  // Dynamic TOTP countdown (30 second period + clock offset)
  const [totpSecondsLeft, setTotpSecondsLeft] = useState<number>(() => {
    const { secondsRemaining } = getTotpRemainingSeconds(challenge.clockOffsetSeconds || 0);
    return secondsRemaining;
  });

  // References to the 6 PIN input boxes
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // 1. Live Ticking TOTP Timer synchronized with standard 30s window and client clock offset
  useEffect(() => {
    const updateTotp = () => {
      const { secondsRemaining } = getTotpRemainingSeconds(challenge.clockOffsetSeconds || 0);
      setTotpSecondsLeft(secondsRemaining);
    };

    updateTotp();
    const timer = setInterval(updateTotp, 1000);
    return () => clearInterval(timer);
  }, [challenge.clockOffsetSeconds]);

  // 2. Resend SMS Cooldown Timer
  useEffect(() => {
    if (resendCooldown <= 0) return;
    const cd = setInterval(() => {
      setResendCooldown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(cd);
  }, [resendCooldown]);

  // Auto-focus first input box on mount
  useEffect(() => {
    if (method !== 'backup_code') {
      inputRefs.current[0]?.focus();
    }
  }, [method]);

  // Automatically load one-time Authenticator QR setup if this identity hasn't paired yet
  useEffect(() => {
    if (!challenge.enrollmentRequired || !challenge.mfaSessionId) return;
    let cancelled = false;
    setEnrollmentLoading(true);
    setEnrollmentError(null);
    fetch('/api/auth/mfa/enroll-challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfaChallengeId: challenge.mfaSessionId })
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok || !data.success) {
          throw new Error(data.error || 'Could not load first-time Authenticator setup.');
        }
        if (!cancelled) {
          setEnrollmentData({
            username: data.username,
            secret: data.secret,
            provisioningUri: data.provisioningUri,
            backupCodes: data.backupCodes,
            issuer: data.issuer
          });
          onAddTerminalLog?.('info', `[MFA PAIRING] Loaded one-time RFC 6238 QR & setup key for unenrolled principal ${challenge.username}.`);
        }
      })
      .catch((err: any) => {
        if (!cancelled) {
          setEnrollmentError(err?.message || 'Unable to load MFA pairing data.');
        }
      })
      .finally(() => {
        if (!cancelled) setEnrollmentLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [challenge.enrollmentRequired, challenge.mfaSessionId, challenge.username, onAddTerminalLog]);

  // Handle digit typing & auto-advance
  const handleDigitChange = (index: number, val: string) => {
    const clean = val.replace(/\D/g, '');
    if (!clean && val !== '') return;

    const newDigits = [...digits];
    if (clean.length > 1) {
      // Pasted or multiple characters entered
      const chars = clean.slice(0, 6).split('');
      chars.forEach((c, i) => {
        if (index + i < 6) newDigits[index + i] = c;
      });
      setDigits(newDigits);
      const nextIdx = Math.min(5, index + chars.length);
      inputRefs.current[nextIdx]?.focus();
      return;
    }

    newDigits[index] = clean;
    setDigits(newDigits);

    // Auto-advance
    if (clean && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    } else if (e.key === 'ArrowLeft' && index > 0) {
      inputRefs.current[index - 1]?.focus();
    } else if (e.key === 'ArrowRight' && index < 5) {
      inputRefs.current[index + 1]?.focus();
    } else if (e.key === 'Enter') {
      const fullCode = digits.join('');
      if (fullCode.length === 6) {
        submitVerification(fullCode);
      }
    }
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').trim();

    // Check if user pasted a recovery code (format: XXXX-XXXX or 8+ alphanumeric)
    if (pasted.includes('-') || pasted.length >= 8) {
      setMethod('backup_code');
      setRecoveryCodeInput(pasted);
      return;
    }

    const numericOnly = pasted.replace(/\D/g, '').slice(0, 6);
    if (!numericOnly) return;
    const newDigits = [...digits];
    for (let i = 0; i < 6; i++) {
      newDigits[i] = numericOnly[i] || '';
    }
    setDigits(newDigits);
    const targetIdx = Math.min(5, numericOnly.length);
    inputRefs.current[targetIdx]?.focus();

    if (numericOnly.length === 6) {
      submitVerification(numericOnly);
    }
  };

  // Submit verification code to API
  const submitVerification = async (codeToVerify?: string) => {
    let cleanCode = '';
    const isRecovery = method === 'backup_code';

    if (isRecovery) {
      cleanCode = (codeToVerify || recoveryCodeInput).trim().toUpperCase();
      if (cleanCode.length < 8) {
        setErrorMsg('Please enter a valid single-use recovery code (format: XXXX-XXXX).');
        return;
      }
    } else {
      const raw = (codeToVerify || digits.join('')).trim();
      cleanCode = raw.replace(/[\s\-]/g, '');
      if (cleanCode.length !== 6 || !/^\d{6}$/.test(cleanCode)) {
        setErrorMsg('Please enter a complete 6-digit verification code.');
        return;
      }
    }

    setLoading(true);
    setErrorMsg(null);

    try {
      onAddTerminalLog?.(
        'post',
        `[MFA] Submitting 2nd factor (${isRecovery ? 'RECOVERY CODE' : method.toUpperCase()}) code for verification...`
      );

      const res = await fetch('/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaSessionId: challenge.mfaSessionId,
          mfaChallengeId: challenge.mfaSessionId,
          username: challenge.username,
          code: cleanCode,
          method: isRecovery ? 'backup_code' : method
        })
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        const remaining = data.attemptsLeft !== undefined ? data.attemptsLeft : Math.max(0, attemptsLeft - 1);
        setAttemptsLeft(remaining);
        setErrorMsg(data.error || data.detail || `Invalid verification code. ${remaining} attempts remaining.`);
        if (data.locked || remaining <= 0) {
          onAddTerminalLog?.('error', `[MFA LOCKED] Challenge invalidated due to repeated failed entries. Please re-authenticate.`);
        } else {
          onAddTerminalLog?.('alert', `[MFA MISMATCH] Verification failed for ${challenge.username}. ${remaining} attempts remaining.`);
        }
        setDigits(['', '', '', '', '', '']);
        if (!isRecovery) inputRefs.current[0]?.focus();
        setLoading(false);
        return;
      }

      // MFA SUCCESS - Guaranteed clean state transition
      setErrorMsg(null);
      onAddTerminalLog?.('success', `[MFA VERIFIED] Factor 2 verified via ${isRecovery ? 'RECOVERY CODE' : method.toUpperCase()}. High-assurance session established.`);
      console.log('[MFA_SUCCESS] Session credentials confirmed for:', data.user?.username);

      const session: AuthSession = {
        user: data.user,
        token: data.token,
        loginTime: new Date().toLocaleTimeString(),
        expiresInSeconds: data.expiresInSeconds || 3600,
        mfaMethod: isRecovery ? 'hardware_token' : method
      };

      onVerifySuccess(session);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Network exception during MFA verification.');
    } finally {
      setLoading(false);
    }
  };

  const isComplete =
    method === 'backup_code'
      ? recoveryCodeInput.trim().length >= 8
      : digits.every((d) => d !== '');

  return (
    <div className={`w-full ${variant === 'page' ? 'max-w-xl mx-auto my-6' : 'w-full'} font-sans`}>
      <div className="glossy-panel rounded-2xl p-6 sm:p-7 shadow-2xl border border-blue-500/30 space-y-6 animate-in fade-in zoom-in-95">
        {/* Top Header & Factor Progress Tracker */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <button
              type="button"
              onClick={onCancel}
              className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Identity Selection</span>
            </button>

            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[11px] font-mono">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Factor 1 (Password) Verified</span>
            </div>
          </div>

          <div className="text-center space-y-1.5 pt-1">
            <div className="w-12 h-12 rounded-2xl bg-blue-500/15 border border-blue-500/30 mx-auto flex items-center justify-center text-blue-400 shadow-inner">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-bold text-white tracking-tight">
              Multi-Factor Authentication
            </h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              Zero-Trust Verification: Complete factor 2 to confirm identity for{' '}
              <span className="text-blue-400 font-semibold">{challenge.username}</span>.
            </p>
          </div>
        </div>

        {/* Identity Overview Strip */}
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center font-bold text-blue-400 uppercase text-xs">
              {challenge.username.slice(0, 2)}
            </div>
            <div>
              <div className="font-semibold text-white flex items-center gap-2">
                <span>{challenge.username}</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-300 font-mono">
                  {challenge.user.role}
                </span>
              </div>
              <div className="text-[11px] text-slate-400 font-mono">
                {challenge.user.department || 'Enterprise Security Unit'}
              </div>
            </div>
          </div>

          <div className="text-right">
            <div className="text-[10px] text-slate-500 uppercase font-mono">Base Risk</div>
            <div className={`font-mono font-bold ${
              challenge.user.base_risk_score >= 50
                ? 'text-rose-400'
                : challenge.user.base_risk_score >= 20
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}>
              {challenge.user.base_risk_score}%
            </div>
          </div>
        </div>

        {/* Method Switcher Tabs: Authenticator, SMS, and Recovery Code */}
        <div className="grid grid-cols-3 gap-1.5 p-1 rounded-xl bg-slate-950/80 border border-slate-800">
          <button
            type="button"
            onClick={() => {
              setMethod('authenticator');
              setErrorMsg(null);
            }}
            className={`flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              method === 'authenticator'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <Smartphone className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">Authenticator</span>
          </button>

          <button
            type="button"
            onClick={() => {
              setMethod('sms');
              setErrorMsg(null);
            }}
            className={`flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              method === 'sms'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <MessageSquare className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">SMS Code</span>
          </button>

          <button
            type="button"
            onClick={() => {
              setMethod('backup_code');
              setErrorMsg(null);
            }}
            className={`flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              method === 'backup_code'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <LifeBuoy className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">Recovery Code</span>
          </button>
        </div>

        {/* METHOD 1: AUTHENTICATOR APP (RFC 6238 TOTP) */}
        {method === 'authenticator' && (
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/90 space-y-3.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-blue-400" />
                RFC 6238 TOTP (30s Window)
              </span>
              <span className="text-[11px] font-mono text-blue-400 font-semibold">
                {totpSecondsLeft}s remaining
              </span>
            </div>

            {/* Live Progress Bar for 30s cycle */}
            <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
              <div
                className="bg-blue-500 h-full transition-all duration-1000 ease-linear rounded-full"
                style={{ width: `${(totpSecondsLeft / 30) * 100}%` }}
              />
            </div>

            {/* First-Time Authenticator Pairing Panel (Shown ONLY when user hasn't paired yet) */}
            {challenge.enrollmentRequired ? (
              enrollmentLoading ? (
                <div className="p-4 rounded-xl bg-slate-950/80 border border-blue-500/30 text-xs text-blue-300 flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Preparing your one-time Authenticator QR code &amp; backup recovery codes...</span>
                </div>
              ) : enrollmentData ? (
                <MfaEnrollmentPanel
                  enrollment={enrollmentData}
                  title="Account Not Paired Yet — Pair Authenticator App Now"
                  subtitle={`Scan this QR code or enter the setup key in Google/Microsoft Authenticator for ${challenge.username}, then enter the 6-digit code below.`}
                />
              ) : enrollmentError ? (
                <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30 text-amber-200 text-xs">
                  {enrollmentError}
                </div>
              ) : null
            ) : (
              /* Authenticator Security Guidance for Already-Paired Users */
              <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-500/30 flex items-start gap-3">
                <div className="p-1.5 rounded bg-blue-500/20 text-blue-400 shrink-0 mt-0.5">
                  <KeyRound className="w-4 h-4" />
                </div>
                <div className="text-xs text-slate-300 leading-relaxed space-y-1">
                  <div>
                    <span className="font-semibold text-white">Time-Based One-Time Password:</span> Open your enrolled Authenticator app (e.g. Google Authenticator, Microsoft Authenticator) and enter the current 6-digit code below.
                  </div>
                  <div className="text-[11px] text-slate-400">
                    New device or didn&apos;t save the QR? Use a saved{' '}
                    <button
                      type="button"
                      onClick={() => setMethod('backup_code')}
                      className="text-amber-300 hover:underline font-medium cursor-pointer"
                    >
                      Recovery Code
                    </button>
                    {' '}or ask an Administrator to click <strong>Reset MFA</strong> in User Database.
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* METHOD 2: SMS OTP CODE */}
        {method === 'sms' && (
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/90 space-y-3.5">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-1.5 text-slate-400">
                <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
                <span>Registered Mobile Device:</span>
              </div>
              <span className="font-mono font-semibold text-white">
                {challenge.phoneMasked || '+1 (555) •••-4829'}
              </span>
            </div>

            {/* Carrier Status Notice */}
            <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-500/30 space-y-2">
              <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>SMS 2FA Gateway Unconfigured</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                Direct telecommunications SMS delivery is not configured in this environment. Please authenticate using your enrolled <strong className="text-blue-300">Authenticator app</strong> or an emergency single-use <strong className="text-amber-300">Recovery Code</strong>.
              </p>
              <div className="pt-1 flex gap-2">
                <button
                  type="button"
                  onClick={() => setMethod('authenticator')}
                  className="px-2.5 py-1 text-xs rounded bg-blue-600/30 hover:bg-blue-600/50 text-blue-200 border border-blue-500/40 cursor-pointer"
                >
                  Switch to Authenticator
                </button>
                <button
                  type="button"
                  onClick={() => setMethod('backup_code')}
                  className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 cursor-pointer"
                >
                  Use Recovery Code
                </button>
              </div>
            </div>
          </div>
        )}

        {/* METHOD 3: RECOVERY CODE */}
        {method === 'backup_code' && (
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/90 space-y-3">
            <div className="flex items-center gap-2 text-xs text-slate-300">
              <LifeBuoy className="w-4 h-4 text-amber-400" />
              <span className="font-semibold text-white">Single-Use Recovery Bypass Code</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Lost your authenticator device? Enter one of your emergency 8-character recovery codes (format: <code className="text-amber-300">XXXX-XXXX</code>). Each code is single-use and will be permanently consumed upon entry.
            </p>

            <div className="relative">
              <input
                type="text"
                value={recoveryCodeInput}
                onChange={(e) => setRecoveryCodeInput(e.target.value.toUpperCase())}
                placeholder="e.g. 7K4N-9P2W"
                maxLength={12}
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-white font-mono text-center text-sm font-bold tracking-widest focus:outline-none focus:border-blue-500 uppercase"
              />
            </div>
          </div>
        )}

        {/* Error Notice */}
        {errorMsg && (
          <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center justify-between gap-3 animate-in shake">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{errorMsg}</span>
            </div>
            {attemptsLeft < 5 && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-900/50 text-rose-200 border border-rose-500/30">
                {attemptsLeft} tries left
              </span>
            )}
          </div>
        )}

        {/* 6-DIGIT CODE INPUT (When not in recovery code mode) */}
        {method !== 'backup_code' && (
          <div className="space-y-2">
            <label className="block text-center text-xs font-mono uppercase text-slate-400 font-medium">
              Enter 6-Digit Verification Code
            </label>

            <div className="flex items-center justify-center gap-2 sm:gap-3">
              {digits.map((digit, idx) => (
                <input
                  key={idx}
                  ref={(el) => { inputRefs.current[idx] = el; }}
                  type="text"
                  inputMode="numeric"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleDigitChange(idx, e.target.value)}
                  onKeyDown={(e) => handleKeyDown(idx, e)}
                  onPaste={handlePaste}
                  disabled={loading}
                  className="w-11 h-13 sm:w-12 sm:h-14 text-center text-xl font-mono font-bold rounded-xl bg-slate-950 border border-slate-700 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 text-white outline-none transition-all shadow-inner"
                />
              ))}
            </div>

            <p className="text-center text-[11px] text-slate-500">
              Paste or type the 6-digit code from your authenticator app
            </p>
          </div>
        )}

        {/* Action Buttons */}
        <div className="space-y-2.5 pt-2">
          <button
            type="button"
            disabled={!isComplete || loading}
            onClick={() => submitVerification()}
            className="w-full glossy-btn py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm shadow-lg shadow-blue-600/30 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-all cursor-pointer"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Verifying Factor 2 with Zero-Trust Edge...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>Verify &amp; Authorize Zero-Trust Session</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            className="w-full py-2.5 rounded-xl border border-slate-800 text-slate-400 hover:text-white hover:bg-slate-900/50 text-xs font-medium transition-colors cursor-pointer"
          >
            Cancel Login
          </button>
        </div>

        {/* Security Compliance Seal */}
        <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500 font-mono">
          <span className="flex items-center gap-1">
            <Lock className="w-3 h-3 text-blue-400" />
            NIST SP 800-207 Zero-Trust MFA
          </span>
          <span className="text-emerald-500">RFC 6238 SHA-1 / SHA-256</span>
        </div>
      </div>
    </div>
  );
};
