import React, { useState, useEffect, useRef } from 'react';
import {
  Smartphone,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  Clock,
  RefreshCw,
  ArrowLeft,
  Copy,
  Check,
  Download,
  Lock,
  LifeBuoy,
  Laptop
} from 'lucide-react';
import { MfaPendingChallenge, AuthSession } from '../types.ts';
import { getTotpRemainingSeconds } from '../utils/mfa.ts';
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
  const [method, setMethod] = useState<'backup_code' | 'authenticator'>(() => {
    if (challenge.enrollmentRequired) return 'backup_code';
    if (challenge.preferredMethod === 'authenticator') return 'authenticator';
    if (challenge.preferredMethod === 'backup_code') return 'backup_code';
    if (challenge.methods?.includes('backup_code')) return 'backup_code';
    return 'authenticator';
  });

  const [digits, setDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [recoveryCodeInput, setRecoveryCodeInput] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [attemptsLeft, setAttemptsLeft] = useState<number>(challenge.attemptsLeft ?? 5);
  const [copiedRecoveryAll, setCopiedRecoveryAll] = useState(false);

  // Separate one-time enrollment payloads keyed by mfaSessionId so laptop-only recovery setup does not hang or overwrite across tab switches
  const [recoveryEnrollmentCodes, setRecoveryEnrollmentCodes] = useState<string[] | null>(null);
  const [recoveryCodesChallengeId, setRecoveryCodesChallengeId] = useState<string | null>(null);
  const [recoveryEnrollmentLoading, setRecoveryEnrollmentLoading] = useState(false);
  const [recoveryEnrollmentError, setRecoveryEnrollmentError] = useState<string | null>(null);

  const [authenticatorEnrollmentData, setAuthenticatorEnrollmentData] = useState<MfaEnrollmentPayload | null>(null);
  const [authenticatorChallengeId, setAuthenticatorChallengeId] = useState<string | null>(null);
  const [authenticatorEnrollmentLoading, setAuthenticatorEnrollmentLoading] = useState(false);
  const [authenticatorEnrollmentError, setAuthenticatorEnrollmentError] = useState<string | null>(null);

  const [challengeSecondsLeft, setChallengeSecondsLeft] = useState<number>(challenge.expiresInSeconds || 300);

  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);
  const recoveryInputRef = useRef<HTMLInputElement | null>(null);
  const onAddTerminalLogRef = useRef(onAddTerminalLog);

  useEffect(() => {
    onAddTerminalLogRef.current = onAddTerminalLog;
  }, [onAddTerminalLog]);

  // Reset enrollment caches cleanly whenever a new MFA challenge is presented
  useEffect(() => {
    setRecoveryEnrollmentCodes(null);
    setRecoveryCodesChallengeId(null);
    setRecoveryEnrollmentLoading(false);
    setRecoveryEnrollmentError(null);
    setAuthenticatorEnrollmentData(null);
    setAuthenticatorChallengeId(null);
    setAuthenticatorEnrollmentLoading(false);
    setAuthenticatorEnrollmentError(null);
    setRecoveryCodeInput('');
    setDigits(['', '', '', '', '', '']);
    setErrorMsg(null);
    setChallengeSecondsLeft(challenge.expiresInSeconds || 300);
  }, [challenge.mfaSessionId, challenge.expiresInSeconds]);

  // Live 5-minute MFA challenge TTL countdown
  useEffect(() => {
    const timer = setInterval(() => {
      setChallengeSecondsLeft((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [challenge.mfaSessionId]);

  useEffect(() => {
    if (challenge.attemptsLeft !== undefined) {
      setAttemptsLeft(challenge.attemptsLeft);
    }
  }, [challenge.attemptsLeft]);

  const [totpSecondsLeft, setTotpSecondsLeft] = useState<number>(() => {
    const { secondsRemaining } = getTotpRemainingSeconds(challenge.clockOffsetSeconds || 0);
    return secondsRemaining;
  });

  useEffect(() => {
    const updateTotp = () => {
      const { secondsRemaining } = getTotpRemainingSeconds(challenge.clockOffsetSeconds || 0);
      setTotpSecondsLeft(secondsRemaining);
    };
    updateTotp();
    const timer = setInterval(updateTotp, 1000);
    return () => clearInterval(timer);
  }, [challenge.clockOffsetSeconds]);

  useEffect(() => {
    if (method === 'authenticator') {
      inputRefs.current[0]?.focus();
    } else {
      recoveryInputRef.current?.focus();
    }
  }, [method]);

  const fetchRecoveryEnrollment = React.useCallback(
    async (signal?: AbortSignal) => {
      if (!challenge.enrollmentRequired || !challenge.mfaSessionId) return;
      setRecoveryEnrollmentLoading(true);
      setRecoveryEnrollmentError(null);

      try {
        const res = await fetch('/api/auth/mfa/enroll-challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mfaChallengeId: challenge.mfaSessionId,
            mode: 'recovery_codes'
          }),
          signal
        });
        const data = await res.json();
        if (signal?.aborted) return;

        if (!res.ok || !data.success || !Array.isArray(data.backupCodes) || data.backupCodes.length === 0) {
          throw new Error(data.error || 'Could not generate laptop recovery codes.');
        }

        setRecoveryEnrollmentCodes(data.backupCodes);
        setRecoveryCodesChallengeId(challenge.mfaSessionId);
        onAddTerminalLogRef.current?.(
          'info',
          `[MFA ENROLLMENT] Issued ${data.backupCodes.length} single-use recovery codes for laptop-only authentication (${challenge.username}).`
        );
      } catch (err: any) {
        if (err?.name === 'AbortError' || signal?.aborted) return;
        setRecoveryEnrollmentError(err?.message || 'Unable to load recovery code enrollment.');
      } finally {
        if (!signal?.aborted) {
          setRecoveryEnrollmentLoading(false);
        }
      }
    },
    [challenge.enrollmentRequired, challenge.mfaSessionId, challenge.username]
  );

  // First-time laptop-only recovery code enrollment (React StrictMode safe via AbortController)
  useEffect(() => {
    if (!challenge.enrollmentRequired || !challenge.mfaSessionId || method !== 'backup_code') {
      return;
    }
    if (recoveryCodesChallengeId === challenge.mfaSessionId && recoveryEnrollmentCodes && recoveryEnrollmentCodes.length > 0) {
      return;
    }

    const controller = new AbortController();
    fetchRecoveryEnrollment(controller.signal);

    return () => {
      controller.abort();
    };
  }, [
    challenge.enrollmentRequired,
    challenge.mfaSessionId,
    method,
    recoveryCodesChallengeId,
    recoveryEnrollmentCodes,
    fetchRecoveryEnrollment
  ]);

  const fetchAuthenticatorEnrollment = React.useCallback(
    async (signal?: AbortSignal) => {
      if (!challenge.enrollmentRequired || !challenge.mfaSessionId) return;
      setAuthenticatorEnrollmentLoading(true);
      setAuthenticatorEnrollmentError(null);

      try {
        const res = await fetch('/api/auth/mfa/enroll-challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mfaChallengeId: challenge.mfaSessionId,
            mode: 'authenticator'
          }),
          signal
        });
        const data = await res.json();
        if (signal?.aborted) return;

        if (!res.ok || !data.success) {
          throw new Error(data.error || 'Could not load first-time Authenticator setup.');
        }

        setAuthenticatorEnrollmentData({
          username: data.username,
          secret: data.secret,
          provisioningUri: data.provisioningUri,
          backupCodes: data.backupCodes,
          issuer: data.issuer
        });
        setAuthenticatorChallengeId(challenge.mfaSessionId);
        if (Array.isArray(data.backupCodes) && data.backupCodes.length > 0) {
          setRecoveryEnrollmentCodes(data.backupCodes);
          setRecoveryCodesChallengeId(challenge.mfaSessionId);
        }
        onAddTerminalLogRef.current?.(
          'info',
          `[MFA PAIRING] Loaded optional RFC 6238 QR & setup key for ${challenge.username}.`
        );
      } catch (err: any) {
        if (err?.name === 'AbortError' || signal?.aborted) return;
        setAuthenticatorEnrollmentError(err?.message || 'Unable to load MFA pairing data.');
      } finally {
        if (!signal?.aborted) {
          setAuthenticatorEnrollmentLoading(false);
        }
      }
    },
    [challenge.enrollmentRequired, challenge.mfaSessionId, challenge.username]
  );

  // Optional first-time Authenticator app pairing when explicitly selected
  useEffect(() => {
    if (!challenge.enrollmentRequired || !challenge.mfaSessionId || method !== 'authenticator') {
      return;
    }
    if (authenticatorChallengeId === challenge.mfaSessionId && authenticatorEnrollmentData) {
      return;
    }

    const controller = new AbortController();
    fetchAuthenticatorEnrollment(controller.signal);

    return () => {
      controller.abort();
    };
  }, [
    challenge.enrollmentRequired,
    challenge.mfaSessionId,
    method,
    authenticatorChallengeId,
    authenticatorEnrollmentData,
    fetchAuthenticatorEnrollment
  ]);

  const handleCopyAllRecoveryCodes = () => {
    if (!recoveryEnrollmentCodes?.length) return;
    navigator.clipboard.writeText(recoveryEnrollmentCodes.join('\n'));
    setCopiedRecoveryAll(true);
    setTimeout(() => setCopiedRecoveryAll(false), 2000);
  };

  const handleDownloadRecoveryCodes = () => {
    if (!recoveryEnrollmentCodes?.length) return;
    const content = [
      'Serverless Cloud Security Verification Framework — Single-Use Recovery Codes',
      `Account: ${challenge.username}`,
      `Issued: ${new Date().toISOString()}`,
      'Store this file safely on your laptop. Each code can be used once to sign in without a phone.',
      '',
      ...recoveryEnrollmentCodes.map((code, idx) => `${idx + 1}. ${code}`)
    ].join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${challenge.username}-recovery-codes.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleDigitChange = (index: number, val: string) => {
    const clean = val.replace(/\D/g, '');
    if (!clean && val !== '') return;

    const newDigits = [...digits];
    if (clean.length > 1) {
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

    if (pasted.includes('-') || pasted.length >= 8) {
      setMethod('backup_code');
      setRecoveryCodeInput(pasted.toUpperCase());
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

  const submitVerification = async (codeToVerify?: string) => {
    let cleanCode = '';
    const isRecovery = method === 'backup_code';

    if (isRecovery) {
      cleanCode = (codeToVerify || recoveryCodeInput).trim().toUpperCase();
      if (cleanCode.replace(/[\s\-]/g, '').length < 8) {
        setErrorMsg('Please enter a valid 8-character single-use recovery code (format: XXXX-XXXX).');
        return;
      }
    } else {
      const raw = (codeToVerify || digits.join('')).trim();
      cleanCode = raw.replace(/[\s\-]/g, '');
      if (cleanCode.length !== 6 || !/^\d{6}$/.test(cleanCode)) {
        setErrorMsg('Please enter a complete 6-digit Authenticator verification code.');
        return;
      }
    }

    setLoading(true);
    setErrorMsg(null);

    try {
      onAddTerminalLog?.(
        'post',
        `[MFA] Submitting 2nd factor (${isRecovery ? 'RECOVERY CODE' : 'AUTHENTICATOR TOTP'}) for verification...`
      );

      const res = await fetch('/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaSessionId: challenge.mfaSessionId,
          mfaChallengeId: challenge.mfaSessionId,
          username: challenge.username,
          code: cleanCode,
          method: isRecovery ? 'backup_code' : 'authenticator'
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

      setErrorMsg(null);
      onAddTerminalLog?.(
        'success',
        `[MFA VERIFIED] Factor 2 verified via ${isRecovery ? 'RECOVERY CODE' : 'AUTHENTICATOR TOTP'}. High-assurance session established.`
      );

      const session: AuthSession = {
        user: data.user,
        token: data.token,
        loginTime: new Date().toLocaleTimeString(),
        expiresInSeconds: data.expiresInSeconds || 3600,
        mfaMethod: data.mfaMethod || (isRecovery ? 'backup_code' : 'authenticator')
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
      ? recoveryCodeInput.trim().replace(/[\s\-]/g, '').length >= 8
      : digits.every((d) => d !== '');

  const remainingCodesCount =
    challenge.recoveryCodesRemaining !== undefined
      ? challenge.recoveryCodesRemaining
      : recoveryEnrollmentCodes?.length;

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
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Zero-Trust Verification: Complete factor 2 for{' '}
              <span className="text-blue-400 font-semibold">{challenge.username}</span>{' '}
              using a single-use Recovery Code on your laptop or an Authenticator app.
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

        {/* Two Method Switcher Tabs: Recovery Code (Laptop-Only) & Authenticator App */}
        <div className="grid grid-cols-2 gap-1.5 p-1 rounded-xl bg-slate-950/80 border border-slate-800">
          <button
            type="button"
            onClick={() => {
              setMethod('backup_code');
              setErrorMsg(null);
            }}
            className={`flex items-center justify-center gap-1.5 py-2.5 px-3 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              method === 'backup_code'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <LifeBuoy className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">Use a Recovery Code</span>
            {typeof remainingCodesCount === 'number' && !challenge.enrollmentRequired && (
              <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                method === 'backup_code' ? 'bg-blue-800/70 text-blue-100' : 'bg-slate-800 text-slate-300'
              }`}>
                {remainingCodesCount}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => {
              setMethod('authenticator');
              setErrorMsg(null);
            }}
            className={`flex items-center justify-center gap-1.5 py-2.5 px-3 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              method === 'authenticator'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <Smartphone className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">
              {challenge.enrollmentRequired ? 'Authenticator App (Optional)' : 'Authenticator code'}
            </span>
          </button>
        </div>

        {/* METHOD 1: SINGLE-USE RECOVERY CODE (LAPTOP-ONLY — NO PHONE NEEDED) */}
        {method === 'backup_code' && (
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/90 space-y-4">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2 text-xs text-slate-200">
                <Laptop className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="font-semibold text-white">
                  {challenge.enrollmentRequired
                    ? 'First-Time Laptop MFA Enrollment (No Phone Needed)'
                    : 'Single-Use Recovery Code Verification'}
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 shrink-0">
                SHA-256 HASHED
              </span>
            </div>

            {challenge.enrollmentRequired ? (
              recoveryEnrollmentLoading ? (
                <div className="p-4 rounded-xl bg-slate-950/80 border border-blue-500/30 text-xs text-blue-300 flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Generating 8 high-entropy single-use recovery codes for your laptop...</span>
                </div>
              ) : recoveryEnrollmentCodes ? (
                <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/35 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                      <LifeBuoy className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>Save These 8 Single-Use Codes Now (Shown Once)</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={handleCopyAllRecoveryCodes}
                        className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-[11px] font-mono flex items-center gap-1 cursor-pointer"
                      >
                        {copiedRecoveryAll ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedRecoveryAll ? 'Copied' : 'Copy All'}</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleDownloadRecoveryCodes}
                        className="px-2.5 py-1 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-200 text-[11px] font-mono flex items-center gap-1 cursor-pointer"
                      >
                        <Download className="w-3 h-3" />
                        <span>Download .txt</span>
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-[11px] text-slate-300 leading-relaxed">
                      Download or copy these codes to your laptop, then <strong className="text-white">click any code below</strong> (or type one) to activate MFA and finish signing in. That code is consumed immediately; the remaining 7 stay valid for future logins.
                    </p>
                    <button
                      type="button"
                      onClick={() => {
                        setRecoveryCodeInput('');
                        fetchRecoveryEnrollment();
                      }}
                      disabled={recoveryEnrollmentLoading}
                      className="text-[10px] font-mono text-amber-300 hover:text-amber-200 underline flex items-center gap-1 cursor-pointer shrink-0"
                    >
                      <RefreshCw className="w-3 h-3" />
                      <span>Generate Fresh Set</span>
                    </button>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {recoveryEnrollmentCodes.map((code) => {
                      const isSelected = recoveryCodeInput.trim().toUpperCase() === code.toUpperCase();
                      return (
                        <button
                          key={code}
                          type="button"
                          onClick={() => {
                            setRecoveryCodeInput(code);
                            setErrorMsg(null);
                            recoveryInputRef.current?.focus();
                          }}
                          title="Click to select this recovery code for immediate verification"
                          className={`px-2.5 py-2 rounded-lg border text-center font-mono text-xs transition-all cursor-pointer select-all ${
                            isSelected
                              ? 'bg-emerald-950/60 border-emerald-400 text-emerald-200 ring-1 ring-emerald-400/50 font-bold shadow-sm'
                              : 'bg-slate-950 border-slate-800 hover:border-amber-400/60 hover:bg-slate-900 text-amber-200'
                          }`}
                        >
                          {code}
                        </button>
                      );
                    })}
                  </div>
                </div>
              ) : recoveryEnrollmentError ? (
                <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-500/30 text-rose-200 text-xs flex items-center justify-between gap-3">
                  <span>{recoveryEnrollmentError}</span>
                  <button
                    type="button"
                    onClick={() => fetchRecoveryEnrollment()}
                    className="px-2.5 py-1 rounded-md bg-rose-500/20 hover:bg-rose-500/30 border border-rose-400/40 text-rose-100 text-[11px] font-mono shrink-0 cursor-pointer flex items-center gap-1"
                  >
                    <RefreshCw className="w-3 h-3" />
                    <span>Retry</span>
                  </button>
                </div>
              ) : null
            ) : (
              <div className="space-y-2">
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Enter one of your saved 8-character recovery codes (format:{' '}
                  <code className="text-amber-300">XXXX-XXXX</code>). Each recovery code is single-use and permanently invalidated once verified.
                </p>
                {challenge.recoveryCodesRemaining === 0 && (
                  <div className="p-3 rounded-lg bg-rose-950/35 border border-rose-500/40 text-rose-200 text-[11px] leading-relaxed">
                    <strong>No recovery codes remaining (0 left).</strong> Please switch to your enrolled Authenticator App or ask an Administrator to generate new recovery codes or reset MFA in User Database.
                  </div>
                )}
              </div>
            )}

            <div className="space-y-1.5">
              <label className="block text-[11px] font-mono uppercase text-slate-400 font-medium">
                Enter Recovery Code
              </label>
              <input
                ref={recoveryInputRef}
                type="text"
                value={recoveryCodeInput}
                onChange={(e) => setRecoveryCodeInput(e.target.value.toUpperCase())}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && isComplete && !loading) {
                    submitVerification();
                  }
                }}
                placeholder="e.g. 7K4N-9P2W"
                maxLength={14}
                disabled={loading}
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-white font-mono text-center text-sm font-bold tracking-widest focus:outline-none focus:border-blue-500 uppercase"
              />
            </div>
          </div>
        )}

        {/* METHOD 2: AUTHENTICATOR APP (RFC 6238 TOTP) */}
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

            <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
              <div
                className="bg-blue-500 h-full transition-all duration-1000 ease-linear rounded-full"
                style={{ width: `${(totpSecondsLeft / 30) * 100}%` }}
              />
            </div>

            {challenge.enrollmentRequired ? (
              authenticatorEnrollmentLoading ? (
                <div className="p-4 rounded-xl bg-slate-950/80 border border-blue-500/30 text-xs text-blue-300 flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Preparing optional Authenticator QR code &amp; backup recovery codes...</span>
                </div>
              ) : authenticatorEnrollmentData ? (
                <MfaEnrollmentPanel
                  enrollment={authenticatorEnrollmentData}
                  title="Optional: Pair an Authenticator App"
                  subtitle={`If you prefer an Authenticator app on another device, scan this QR code for ${challenge.username} and enter the 6-digit code below. Otherwise switch back to Use a Recovery Code for laptop-only login.`}
                />
              ) : authenticatorEnrollmentError ? (
                <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30 text-amber-200 text-xs flex items-center justify-between gap-3">
                  <span>{authenticatorEnrollmentError}</span>
                  <button
                    type="button"
                    onClick={() => fetchAuthenticatorEnrollment()}
                    className="px-2.5 py-1 rounded-md bg-amber-500/20 hover:bg-amber-500/30 border border-amber-400/40 text-amber-100 text-[11px] font-mono shrink-0 cursor-pointer flex items-center gap-1"
                  >
                    <RefreshCw className="w-3 h-3" />
                    <span>Retry</span>
                  </button>
                </div>
              ) : null
            ) : (
              <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-500/30 flex items-start gap-3">
                <div className="p-1.5 rounded bg-blue-500/20 text-blue-400 shrink-0 mt-0.5">
                  <KeyRound className="w-4 h-4" />
                </div>
                <div className="text-xs text-slate-300 leading-relaxed space-y-1">
                  <div>
                    <span className="font-semibold text-white">Time-Based One-Time Password:</span> Enter the current 6-digit code from your paired Authenticator app.
                  </div>
                  <div className="text-[11px] text-slate-400">
                    No phone available? Switch to{' '}
                    <button
                      type="button"
                      onClick={() => {
                        setMethod('backup_code');
                        setErrorMsg(null);
                      }}
                      className="text-amber-300 hover:underline font-medium cursor-pointer"
                    >
                      Use a Recovery Code
                    </button>
                    {' '}to sign in directly from your laptop.
                  </div>
                </div>
              </div>
            )}
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

        {/* 6-DIGIT CODE INPUT (When Authenticator tab active) */}
        {method === 'authenticator' && (
          <div className="space-y-2">
            <label className="block text-center text-xs font-mono uppercase text-slate-400 font-medium">
              Enter 6-Digit Authenticator Code
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

        {/* Security Compliance Seal & Challenge TTL */}
        <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[10px] text-slate-500 font-mono">
          <span className="flex items-center gap-1">
            <Lock className="w-3 h-3 text-blue-400" />
            NIST SP 800-207 Zero-Trust MFA
          </span>
          <span className={challengeSecondsLeft <= 30 ? 'text-rose-400 font-semibold' : 'text-slate-400'}>
            {challengeSecondsLeft > 0
              ? `Challenge valid ${Math.floor(challengeSecondsLeft / 60)}:${String(challengeSecondsLeft % 60).padStart(2, '0')}`
              : 'Challenge expired — please cancel and sign in again'}
          </span>
          <span className="text-emerald-500">SHA-256 Recovery &amp; RFC 6238 TOTP</span>
        </div>
      </div>
    </div>
  );
};
