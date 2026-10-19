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
  QrCode,
  Shield,
  Fingerprint
} from 'lucide-react';
import { MfaPendingChallenge, AuthSession, User } from '../types.ts';

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
  const [method, setMethod] = useState<'authenticator' | 'sms'>('authenticator');
  const [digits, setDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [attemptsLeft, setAttemptsLeft] = useState<number>(5);
  const [copiedCode, setCopiedCode] = useState(false);
  const [resendCooldown, setResendCooldown] = useState<number>(0);
  const [smsNotification, setSmsNotification] = useState<{
    code: string;
    timestamp: string;
  } | null>({
    code: challenge.demoSmsCode || '847291',
    timestamp: 'Just now'
  });

  // Dynamic TOTP countdown calculation (30 second period)
  const [totpSecondsLeft, setTotpSecondsLeft] = useState<number>(() => {
    return 30 - (Math.floor(Date.now() / 1000) % 30);
  });
  const [currentTotpCode, setCurrentTotpCode] = useState<string>(challenge.demoTotpCode || '582914');

  // References to the 6 PIN input boxes
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // 1. Ticking TOTP Timer
  useEffect(() => {
    const timer = setInterval(() => {
      const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
      setTotpSecondsLeft(remaining);

      // Recalculate code on cycle
      if (remaining === 30) {
        const step = Math.floor(Date.now() / 30000);
        let hash = 0;
        const str = `${challenge.username}_totp_secret_${step}`;
        for (let i = 0; i < str.length; i++) {
          hash = (hash << 5) - hash + str.charCodeAt(i);
          hash |= 0;
        }
        const code = (Math.abs(hash) % 900000 + 100000).toString();
        setCurrentTotpCode(code);
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [challenge.username]);

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
    inputRefs.current[0]?.focus();
  }, []);

  // Handle digit typing & auto-advance
  const handleDigitChange = (index: number, val: string) => {
    // Only accept numeric characters
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
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (!pasted) return;
    const newDigits = [...digits];
    for (let i = 0; i < 6; i++) {
      newDigits[i] = pasted[i] || '';
    }
    setDigits(newDigits);
    const targetIdx = Math.min(5, pasted.length);
    inputRefs.current[targetIdx]?.focus();

    if (pasted.length === 6) {
      submitVerification(pasted);
    }
  };

  // Submit verification code to API
  const submitVerification = async (codeToVerify?: string) => {
    const code = (codeToVerify || digits.join('')).trim();
    if (code.length !== 6) {
      setErrorMsg('Please enter a complete 6-digit verification code.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);

    try {
      onAddTerminalLog?.('post', `[MFA] Submitting 2nd factor (${method.toUpperCase()}) code for verification...`);
      const res = await fetch('/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaSessionId: challenge.mfaSessionId,
          code,
          method
        })
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        setErrorMsg(data.error || 'Invalid verification code. Please check your code and try again.');
        if (data.attemptsLeft !== undefined) {
          setAttemptsLeft(data.attemptsLeft);
        }
        if (data.locked) {
          onAddTerminalLog?.('error', `[MFA LOCKED] Challenge invalidated due to repeated failed entries.`);
        } else {
          onAddTerminalLog?.('alert', `[MFA MISMATCH] Incorrect 6-digit code entered for ${challenge.username}.`);
        }
        setDigits(['', '', '', '', '', '']);
        inputRefs.current[0]?.focus();
        setLoading(false);
        return;
      }

      // MFA SUCCESS
      onAddTerminalLog?.('success', `[MFA VERIFIED] Factor 2 verified via ${method.toUpperCase()}. High-assurance session established.`);
      const session: AuthSession = {
        user: data.user,
        token: data.token,
        loginTime: new Date().toLocaleTimeString(),
        expiresInSeconds: data.expiresInSeconds || 3600,
        mfaMethod: method
      };

      onVerifySuccess(session);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Network exception during MFA verification.');
    } finally {
      setLoading(false);
    }
  };

  // Resend SMS handler
  const handleResendSms = async () => {
    if (resendCooldown > 0) return;
    setLoading(true);
    setErrorMsg(null);

    try {
      const res = await fetch('/api/auth/mfa/send-sms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaSessionId: challenge.mfaSessionId })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setResendCooldown(30);
        setSmsNotification({
          code: data.demoSmsCode,
          timestamp: 'Just now'
        });
        onAddTerminalLog?.('info', `[MFA SMS] Fresh one-time passcode dispatched to ${challenge.phoneMasked}.`);
      } else {
        setErrorMsg(data.error || 'Failed to dispatch new SMS code.');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Failed to resend SMS.');
    } finally {
      setLoading(false);
    }
  };

  // 1-Click Auto-fill helper
  const handleAutoFillCode = (code: string) => {
    const chars = code.slice(0, 6).split('');
    setDigits(chars);
    setErrorMsg(null);
    submitVerification(code);
  };

  const isComplete = digits.every((d) => d !== '');

  return (
    <div className={`w-full ${variant === 'page' ? 'max-w-xl mx-auto my-6' : 'w-full'} font-sans`}>
      <div className="glossy-panel rounded-2xl p-6 sm:p-7 shadow-2xl border border-blue-500/30 space-y-6 animate-in fade-in zoom-in-95">
        {/* Top Header & Factor Progress Tracker */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <button
              type="button"
              onClick={onCancel}
              className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
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

        {/* Method Switcher Tabs */}
        <div className="grid grid-cols-2 gap-2 p-1 rounded-xl bg-slate-950/80 border border-slate-800">
          <button
            type="button"
            onClick={() => {
              setMethod('authenticator');
              setErrorMsg(null);
            }}
            className={`flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-medium transition-all ${
              method === 'authenticator'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <Smartphone className="w-4 h-4" />
            <span>Authenticator App</span>
          </button>

          <button
            type="button"
            onClick={() => {
              setMethod('sms');
              setErrorMsg(null);
            }}
            className={`flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-medium transition-all ${
              method === 'sms'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <MessageSquare className="w-4 h-4" />
            <span>SMS Security Code</span>
          </button>
        </div>

        {/* METHOD 1: AUTHENTICATOR APP (TOTP) */}
        {method === 'authenticator' && (
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/90 space-y-3.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-blue-400" />
                Time-based OTP (TOTP 30s Window)
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

            {/* Authenticator Demo Code Helper Banner */}
            <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-500/30 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded bg-blue-500/20 text-blue-400">
                  <KeyRound className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[10px] uppercase font-mono text-slate-400">Active Authenticator Code:</div>
                  <div className="font-mono text-base font-bold text-white tracking-widest">
                    {currentTotpCode.slice(0, 3)} {currentTotpCode.slice(3, 6)}
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => handleAutoFillCode(currentTotpCode)}
                className="glossy-btn px-3 py-1.5 rounded-lg text-xs text-blue-300 hover:text-white font-medium flex items-center gap-1.5 border border-blue-500/40 bg-blue-600/30"
              >
                <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                <span>Auto-fill</span>
              </button>
            </div>
          </div>
        )}

        {/* METHOD 2: SMS OTP CODE */}
        {method === 'sms' && (
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/90 space-y-3.5">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-1.5 text-slate-400">
                <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
                <span>Code sent to registered mobile:</span>
              </div>
              <span className="font-mono font-semibold text-white">
                {challenge.phoneMasked || '+1 (555) •••-4829'}
              </span>
            </div>

            {/* Simulated Incoming SMS Push Banner */}
            {smsNotification && (
              <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/30 space-y-2">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                    <Send className="w-3 h-3" />
                    Simulated Carrier SMS Push Alert
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">{smsNotification.timestamp}</span>
                </div>
                <div className="text-xs text-slate-300 font-mono">
                  &ldquo;[Zero-Trust Security] Your verification code is{' '}
                  <span className="text-emerald-300 font-bold">{smsNotification.code}</span>. Valid for 5 minutes.&rdquo;
                </div>
                <div className="flex items-center justify-between pt-1">
                  <button
                    type="button"
                    onClick={() => handleAutoFillCode(smsNotification.code)}
                    className="text-xs text-emerald-300 hover:text-emerald-200 font-medium underline flex items-center gap-1"
                  >
                    <span>Auto-fill {smsNotification.code}</span>
                  </button>

                  <button
                    type="button"
                    disabled={resendCooldown > 0 || loading}
                    onClick={handleResendSms}
                    className="text-xs text-slate-400 hover:text-white disabled:opacity-50 flex items-center gap-1"
                  >
                    <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
                    <span>{resendCooldown > 0 ? `Resend (${resendCooldown}s)` : 'Resend SMS'}</span>
                  </button>
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

        {/* 6-DIGIT CODE INPUT */}
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
            Paste or type code • Universal demo bypass: <code className="text-slate-400">123456</code>
          </p>
        </div>

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
            className="w-full py-2.5 rounded-xl border border-slate-800 text-slate-400 hover:text-white hover:bg-slate-900/50 text-xs font-medium transition-colors"
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
          <span className="text-emerald-500">Edge Cryptographic Signatures</span>
        </div>
      </div>
    </div>
  );
};
