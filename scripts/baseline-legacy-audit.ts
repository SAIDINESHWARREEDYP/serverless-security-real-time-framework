/**
 * Auditable Legacy Audit Baseline CLI
 *
 * Inspects the persistent audit ledger and, when --apply is passed, seals pre-epoch
 * unchained/legacy rows inside `audit_ledger_epochs` WITHOUT modifying or deleting any
 * historical rows, while preserving strict distinction between Archived Legacy History
 * and Cryptographically Verified Modern Epoch History.
 *
 * Usage:
 *   npm run audit:baseline -- --inspect
 *   npm run audit:baseline -- --apply [--cutoff=<id>] [--admin=<username>] [--label=<label>] [--reason=<text>]
 */

import 'dotenv/config';
import { auditRepository } from '../server/repositories/audit.repository.ts';

function parseArgs(argv: string[]) {
  const args: Record<string, string | boolean> = {};
  for (const item of argv) {
    if (!item.startsWith('--')) continue;
    const eqIdx = item.indexOf('=');
    if (eqIdx === -1) {
      args[item.slice(2)] = true;
    } else {
      args[item.slice(2, eqIdx)] = item.slice(eqIdx + 1);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const shouldApply = Boolean(args.apply);
  const preStatus = auditRepository.verifyIntegrityChain();
  const anchorStatus = auditRepository.getAnchorStatus();

  if (!shouldApply) {
    console.log(
      JSON.stringify(
        {
          mode: 'INSPECT_ONLY',
          verificationStatus: preStatus.verificationStatus,
          chainIntact: preStatus.chainIntact,
          fullLedgerVerified: preStatus.fullLedgerVerified,
          verifiedEpochIntact: preStatus.verifiedEpochIntact,
          totalInLedger: preStatus.totalInLedger,
          legacyRecordsCount: preStatus.legacyRecordsCount,
          legacyCutoffMaxId: preStatus.legacyCutoffMaxId,
          legacySnapshotVerified: preStatus.legacySnapshotVerified,
          verifiedEpochCount: preStatus.verifiedEpochCount,
          suggestedLegacyCutoffMaxId: preStatus.suggestedLegacyCutoffMaxId,
          brokenLinksCount: preStatus.brokenLinks.length,
          anchor: {
            present: anchorStatus.present,
            verified: anchorStatus.verified,
            activeKeyId: anchorStatus.activeKeyId,
            keyFingerprint: anchorStatus.keyFingerprint,
            keySource: anchorStatus.keySource
          }
        },
        null,
        2
      )
    );
    return;
  }

  const cutoffRaw = args.cutoff;
  const cutoffMaxId =
    typeof cutoffRaw === 'string' && cutoffRaw.trim().length > 0 ? Number(cutoffRaw.trim()) : undefined;
  const adminUsername =
    typeof args.admin === 'string' && args.admin.trim().length > 0 ? args.admin.trim() : 'secops_admin';
  const epochLabel = typeof args.label === 'string' ? args.label.trim() : undefined;
  const reason = typeof args.reason === 'string' ? args.reason.trim() : undefined;

  const result = auditRepository.baselineLegacyRecords({
    adminUsername,
    cutoffMaxId,
    epochLabel,
    reason
  });
  const postStatus = auditRepository.verifyIntegrityChain();

  console.log(
    JSON.stringify(
      {
        mode: 'BASELINE_APPLIED',
        epoch: result.epoch,
        auditEventId: result.auditEventId,
        postVerification: {
          verificationStatus: postStatus.verificationStatus,
          chainIntact: postStatus.chainIntact,
          fullLedgerVerified: postStatus.fullLedgerVerified,
          verifiedEpochIntact: postStatus.verifiedEpochIntact,
          legacyRecordsCount: postStatus.legacyRecordsCount,
          legacySnapshotVerified: postStatus.legacySnapshotVerified,
          verifiedEpochCount: postStatus.verifiedEpochCount,
          anchorVerified: postStatus.anchorVerified
        }
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  console.error('[audit:baseline] Failed:', err?.message || err);
  process.exit(1);
});
