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
  ShieldCheck
} from 'lucide-react';

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

  return (
    <div className="p-4 rounded-xl bg-slate-950/90 border border-emerald-500/35 space-y-4 text-xs shadow-lg">
      <div className="flex items-start gap-2.5">
        <div className="p-2 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 shrink-0">
          <QrCode className="w-4 h-4" />
        </div>
        <div>
          <h4 className="font-bold text-white text-xs sm:text-sm flex items-center gap-2 flex-wrap">
            <span>{title}</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              RFC 6238
            </span>
          </h4>
          <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
            {subtitle}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-4 items-center">
        {/* Offline-generated QR Code */}
        <div className="mx-auto sm:mx-0 p-2.5 bg-white rounded-xl border border-slate-700 shadow-inner flex flex-col items-center">
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
            <div className="text-[10px] uppercase font-mono text-slate-400 flex items-center gap-1.5">
              <KeyRound className="w-3 h-3 text-blue-400" />
              <span>Manual Setup Key (Time-Based / 30s)</span>
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 px-2.5 py-2 rounded-lg bg-slate-900 border border-slate-800 text-emerald-300 font-mono text-[11px] break-all select-all">
                {formattedSecret}
              </code>
              <button
                type="button"
                onClick={handleCopySecret}
                className="px-2.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-medium flex items-center gap-1 shrink-0 cursor-pointer"
                title="Copy Base32 setup key"
              >
                {copiedSecret ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedSecret ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <a
              href={enrollment.provisioningUri}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-blue-300 text-[11px] font-semibold transition-colors"
            >
              <Smartphone className="w-3.5 h-3.5" />
              <span>Open in Authenticator App</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <ol className="text-[11px] text-slate-400 space-y-1 list-decimal list-inside">
            <li>Open Google Authenticator or Microsoft Authenticator and tap <strong className="text-slate-200">+</strong>.</li>
            <li>Choose <strong className="text-slate-200">Scan a QR code</strong> (or <strong className="text-slate-200">Enter a setup key</strong> and paste the key above).</li>
            <li>Enter the generated 6-digit code below to verify and lock pairing.</li>
          </ol>
        </div>
      </div>

      {/* Single-Use Emergency Recovery Codes */}
      {enrollment.backupCodes && enrollment.backupCodes.length > 0 && (
        <div className="p-3 rounded-xl bg-amber-950/20 border border-amber-500/30 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-amber-300 font-semibold text-[11px]">
              <LifeBuoy className="w-3.5 h-3.5 text-amber-400" />
              <span>Emergency Single-Use Recovery Codes (Save These Now)</span>
            </div>
            <button
              type="button"
              onClick={handleCopyBackupCodes}
              className="px-2 py-1 rounded bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-200 text-[10px] font-mono flex items-center gap-1 cursor-pointer"
            >
              {copiedCodes ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedCodes ? 'Copied All' : 'Copy All'}</span>
            </button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
            {enrollment.backupCodes.map((code) => (
              <div
                key={code}
                className="px-2 py-1 rounded bg-slate-900/90 border border-slate-800 text-center font-mono text-[11px] text-amber-200 select-all"
              >
                {code}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex items-center gap-1.5 text-[10px] text-slate-500 font-mono">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
        <span>This pairing key is shown only while unpaired and is sealed immediately after your first verified 6-digit code.</span>
      </div>
    </div>
  );
};
