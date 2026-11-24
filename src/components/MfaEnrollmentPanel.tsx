import React, { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import {
  QrCode,
  Copy,
  Check,
  Smartphone,
  LifeBuoy,
  ExternalLink,
  KeyRound,
  ShieldCheck,
  Download
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext.tsx';

export interface MfaEnrollmentPayload {
  username?: string;
  secret: string;
  provisioningUri: string;
  backupCodes?: string[];
  issuer?: string;
}

interface MfaEnrollmentPanelProps {
  enrollment: MfaEnrollmentPayload;
  title?: string;
  subtitle?: string;
}

export const MfaEnrollmentPanel: React.FC<MfaEnrollmentPanelProps> = ({
  enrollment,
  title = 'Pair Your Authenticator App (One-Time Setup)',
  subtitle = 'Scan the QR code below or enter the setup key manually in Google Authenticator, Microsoft Authenticator, or Authy.'
}) => {
  const { isLight } = useTheme();
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!enrollment.provisioningUri) return;
    QRCode.toDataURL(enrollment.provisioningUri, {
      width: 192,
      margin: 2,
      color: {
        dark: '#0f172a',
        light: '#ffffff'
      }
    })
      .then((url) => {
        if (!cancelled) setQrDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setQrDataUrl(null);
      });
    return () => {
      cancelled = true;
    };
  }, [enrollment.provisioningUri]);

  const formattedSecret = enrollment.secret.replace(/(.{4})/g, '$1 ').trim();

  const handleCopySecret = () => {
    navigator.clipboard.writeText(enrollment.secret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  const handleCopyBackupCodes = () => {
    if (!enrollment.backupCodes?.length) return;
    navigator.clipboard.writeText(enrollment.backupCodes.join('\n'));
    setCopiedCodes(true);
    setTimeout(() => setCopiedCodes(false), 2000);
  };

  const handleDownloadBackupCodes = () => {
    if (!enrollment.backupCodes?.length) return;
    const content = [
      'Serverless Cloud Security Verification Framework — Single-Use Recovery Codes',
      `Account: ${enrollment.username || 'identity'}`,
      `Issued: ${new Date().toISOString()}`,
      'Store these codes safely on your laptop. Each code works once.',
      '',
      ...enrollment.backupCodes.map((c, idx) => `${idx + 1}. ${c}`)
    ].join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${enrollment.username || 'account'}-recovery-codes.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`p-4 rounded-xl border space-y-4 text-xs shadow-lg ${
      isLight
        ? 'bg-white border-emerald-300 shadow-slate-900/5'
        : 'bg-slate-950/90 border-emerald-500/35'
    }`}>
      <div className="flex items-start gap-2.5">
        <div className={`p-2 rounded-lg border shrink-0 ${
          isLight
            ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
            : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400'
        }`}>
          <QrCode className="w-4 h-4" />
        </div>
        <div>
          <h4 className={`font-bold text-xs sm:text-sm flex items-center gap-2 flex-wrap ${
            isLight ? 'text-slate-900' : 'text-white'
          }`}>
            <span>{title}</span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              isLight
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
            }`}>
              RFC 6238
            </span>
          </h4>
          <p className={`text-[11px] mt-0.5 leading-relaxed ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
            {subtitle}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-4 items-center">
        {/* Offline-generated QR Code */}
        <div className={`mx-auto sm:mx-0 p-2.5 bg-white rounded-xl border shadow-inner flex flex-col items-center ${
          isLight ? 'border-slate-300' : 'border-slate-700'
        }`}>
          {qrDataUrl ? (
            <img
              src={qrDataUrl}
              alt="TOTP Authenticator QR Code"
              className="w-40 h-40 object-contain rounded"
            />
          ) : (
            <div className="w-40 h-40 flex items-center justify-center text-slate-600 text-[11px] font-mono">
              Generating QR...
            </div>
          )}
          <span className="text-[10px] text-slate-600 font-mono mt-1 font-semibold">
            {enrollment.issuer || 'ServerlessSecOps'}
          </span>
        </div>

        {/* Manual Setup Key & Quick Mobile Link */}
        <div className="space-y-3 min-w-0">
          <div className="space-y-1">
            <div className={`text-[10px] uppercase font-mono flex items-center gap-1.5 ${
              isLight ? 'text-slate-600' : 'text-slate-400'
            }`}>
              <KeyRound className={`w-3 h-3 ${isLight ? 'text-blue-600' : 'text-blue-400'}`} />
              <span>Manual Setup Key (Time-Based / 30s)</span>
            </div>
            <div className="flex items-center gap-2">
              <code className={`flex-1 px-2.5 py-2 rounded-lg border font-mono text-[11px] break-all select-all ${
                isLight
                  ? 'bg-slate-50 border-slate-200 text-emerald-700 font-semibold'
                  : 'bg-slate-900 border-slate-800 text-emerald-300'
              }`}>
                {formattedSecret}
              </code>
              <button
                type="button"
                onClick={handleCopySecret}
                className={`px-2.5 py-2 rounded-lg border text-[11px] font-medium flex items-center gap-1 shrink-0 cursor-pointer ${
                  isLight
                    ? 'bg-slate-100 hover:bg-slate-200 text-slate-800 border-slate-300'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                }`}
                title="Copy Base32 setup key"
              >
                {copiedSecret ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedSecret ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <a
              href={enrollment.provisioningUri}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-[11px] font-semibold transition-colors ${
                isLight
                  ? 'bg-blue-50 hover:bg-blue-100 border-blue-200 text-blue-700'
                  : 'bg-blue-600/20 hover:bg-blue-600/30 border-blue-500/40 text-blue-300'
              }`}
            >
              <Smartphone className="w-3.5 h-3.5" />
              <span>Open in Authenticator App</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <ol className={`text-[11px] space-y-1 list-decimal list-inside ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
            <li>Open Google Authenticator or Microsoft Authenticator and tap <strong className={isLight ? 'text-slate-900' : 'text-slate-200'}>+</strong>.</li>
            <li>Choose <strong className={isLight ? 'text-slate-900' : 'text-slate-200'}>Scan a QR code</strong> (or <strong className={isLight ? 'text-slate-900' : 'text-slate-200'}>Enter a setup key</strong> and paste the key above).</li>
            <li>Enter the generated 6-digit code below to verify and lock pairing.</li>
          </ol>
        </div>
      </div>

      {/* Single-Use Emergency Recovery Codes */}
      {enrollment.backupCodes && enrollment.backupCodes.length > 0 && (
        <div className={`p-3 rounded-xl border space-y-2 ${
          isLight
            ? 'bg-amber-50/80 border-amber-200'
            : 'bg-amber-950/20 border-amber-500/30'
        }`}>
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className={`flex items-center gap-1.5 font-semibold text-[11px] ${
              isLight ? 'text-amber-800' : 'text-amber-300'
            }`}>
              <LifeBuoy className={`w-3.5 h-3.5 ${isLight ? 'text-amber-600' : 'text-amber-400'}`} />
              <span>Emergency Single-Use Recovery Codes (Save These Now)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handleCopyBackupCodes}
                className={`px-2 py-1 rounded border text-[10px] font-mono flex items-center gap-1 cursor-pointer ${
                  isLight
                    ? 'bg-amber-100 hover:bg-amber-200 border-amber-300 text-amber-900'
                    : 'bg-amber-500/15 hover:bg-amber-500/25 border-amber-500/30 text-amber-200'
                }`}
              >
                {copiedCodes ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                <span>{copiedCodes ? 'Copied All' : 'Copy All'}</span>
              </button>
              <button
                type="button"
                onClick={handleDownloadBackupCodes}
                className={`px-2 py-1 rounded border text-[10px] font-mono flex items-center gap-1 cursor-pointer ${
                  isLight
                    ? 'bg-white hover:bg-slate-100 border-slate-300 text-slate-800'
                    : 'bg-slate-900 hover:bg-slate-800 border-slate-700 text-amber-200'
                }`}
              >
                <Download className="w-3 h-3" />
                <span>Download .txt</span>
              </button>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
            {enrollment.backupCodes.map((code) => (
              <div
                key={code}
                className={`px-2 py-1 rounded border text-center font-mono text-[11px] tabular-nums select-all ${
                  isLight
                    ? 'bg-white border-amber-200 text-slate-900 font-semibold'
                    : 'bg-slate-900/90 border-slate-800 text-amber-200'
                }`}
              >
                {code}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex items-center gap-1.5 text-[10px] text-slate-500 font-mono">
        <ShieldCheck className={`w-3.5 h-3.5 shrink-0 ${isLight ? 'text-emerald-600' : 'text-emerald-400'}`} />
        <span>This pairing key is shown only while unpaired and is sealed immediately after your first verified 6-digit code.</span>
      </div>
    </div>
  );
};
