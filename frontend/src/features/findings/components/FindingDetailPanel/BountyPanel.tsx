import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useScopeStore } from '@/stores/scopeStore';
import { classifyAgainstScope } from '@/utils/scopeParser';
import { estimateBounty } from './helpers';
import type { Finding } from '@/types/api';

interface BountyPanelProps {
  finding: Finding;
  bountyValue: number;
  bountyCurrency: string;
  bountySource: string;
  alreadyReported: boolean;
  sanitizePII: boolean;
  savingBounty: boolean;
  onBountyValueChange: (v: number) => void;
  onBountyCurrencyChange: (v: string) => void;
  onBountySourceChange: (v: string) => void;
  onAlreadyReportedChange: (v: boolean) => void;
  onSanitizePIIChange: (v: boolean) => void;
  onSaveBounty: () => void;
  onCopyReport: () => void;
}

export function BountyPanel({
  finding,
  bountyValue,
  bountyCurrency,
  bountySource,
  alreadyReported,
  sanitizePII,
  savingBounty,
  onBountyValueChange,
  onBountyCurrencyChange,
  onBountySourceChange,
  onAlreadyReportedChange,
  onSanitizePIIChange,
  onSaveBounty,
  onCopyReport,
}: BountyPanelProps) {
  const parsedScope = useScopeStore((s) => s.parsed);
  const scopeClassification = useMemo(() => {
    const asset = finding.url || finding.host || finding.target || '';
    return classifyAgainstScope(asset, parsedScope);
  }, [finding, parsedScope]);

  const score = finding.cvss_v4_score ?? finding.cvss_score ?? 0;
  const epss = finding.threat_intel?.epss_score ?? finding.epss_score ?? 0;
  const criticality = finding.asset_criticality ?? 1.0;
  const range = estimateBounty(score, epss, criticality);

  return (
    <div className="space-y-6" data-testid="finding-bounty-panel">
      <div className="glass-panel border border-line rounded-xl p-4">
        <div className="text-[10px] font-black uppercase tracking-widest text-muted mb-2">Scope Compliance</div>
        {scopeClassification.status === 'in_scope' ? (
          <div className="p-3 bg-ok/10 border border-ok/20 rounded-lg text-xs text-ok flex flex-col gap-1">
            <span className="font-bold">✓ IN SCOPE</span>
            <span className="text-[10px] text-text/80 leading-normal">
              Matches pattern: <code className="bg-surface-2 px-1 rounded">{scopeClassification.matchingEntry?.pattern}</code>
            </span>
            {scopeClassification.matchingEntry?.notes && (
              <p className="text-[9px] text-muted italic mt-1">Notes: {scopeClassification.matchingEntry.notes}</p>
            )}
          </div>
        ) : scopeClassification.status === 'out_of_scope' ? (
          <div className="p-3 bg-bad/10 border border-bad/20 rounded-lg text-xs text-bad flex flex-col gap-1 animate-pulse">
            <span className="font-bold">⚠️ OUT OF SCOPE</span>
            <span className="text-[10px] text-text/80 leading-normal">
              Matches pattern: <code className="bg-surface-2 px-1 rounded text-bad">{scopeClassification.matchingEntry?.pattern}</code>
            </span>
            <p className="text-[9px] text-muted italic mt-1">Submission may result in negative reputation or ban.</p>
          </div>
        ) : (
          <div className="p-3 bg-zinc-900/40 border border-line rounded-lg text-xs text-muted flex flex-col gap-1">
            <span className="font-bold">? NO SCOPE DATA</span>
            <span className="text-[10px] text-muted leading-normal">
              Verify with the target's program policy manually before submitting.
            </span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-panel border border-line rounded-xl p-4 space-y-4">
          <div>
            <div className="text-[10px] font-black uppercase tracking-widest text-muted mb-1">CVSS-to-Bounty Estimator</div>
            <div className="text-sm font-semibold text-text">Estimated Payout Range:</div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-black text-accent">${range.min.toLocaleString()}</span>
              <span className="text-muted text-xs font-mono">—</span>
              <span className="text-3xl font-black text-accent">${range.max.toLocaleString()}</span>
              <span className="text-[10px] font-mono text-muted uppercase">USD</span>
            </div>
            <div className="text-[9px] text-muted font-mono mt-2 leading-relaxed">
              EPSS Multiplier: {epss > 0.1 ? '1.20x (+20% Wild Activity)' : '1.00x'} <br />
              Asset Multiplier: {finding.asset_criticality ? `${finding.asset_criticality.toFixed(2)}x` : '1.00x'}
            </div>
          </div>

          <div className="pt-2 border-t border-line space-y-3">
            <div className="text-[10px] font-black uppercase tracking-widest text-muted">Bounty Details</div>
            <div className="grid grid-cols-3 gap-2">
              <label className="block text-[10px] text-muted">
                Amount ($)
                <input
                  type="number"
                  value={bountyValue}
                  onChange={(e) => onBountyValueChange(Number(e.target.value))}
                  className="w-full mt-1 bg-surface-hover border border-line rounded-lg py-1.5 px-2 text-xs font-mono text-text focus:border-accent/50 outline-none"
                />
              </label>
              <label className="block text-[10px] text-muted">
                Currency
                <input
                  type="text"
                  value={bountyCurrency}
                  onChange={(e) => onBountyCurrencyChange(e.target.value)}
                  className="w-full mt-1 bg-surface-hover border border-line rounded-lg py-1.5 px-2 text-xs font-mono text-text focus:border-accent/50 outline-none uppercase"
                />
              </label>
              <label className="block text-[10px] text-muted">
                Platform
                <select
                  value={bountySource}
                  onChange={(e) => onBountySourceChange(e.target.value)}
                  className="w-full mt-1 bg-surface border border-line rounded-lg py-1.5 px-2 text-xs font-mono text-text focus:border-accent/50 outline-none"
                >
                  <option value="estimate">Estimate</option>
                  <option value="hackerone">HackerOne</option>
                  <option value="bugcrowd">Bugcrowd</option>
                  <option value="intigriti">Intigriti</option>
                  <option value="synack">Synack</option>
                  <option value="manual">Manual</option>
                </select>
              </label>
            </div>
            <div className="flex justify-between items-center gap-4 pt-1">
              <label className="flex items-center gap-2 text-[10px] text-muted cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={alreadyReported}
                  onChange={(e) => onAlreadyReportedChange(e.target.checked)}
                  className="accent-accent"
                />
                Already Submitted
              </label>
              <button
                type="button"
                onClick={onSaveBounty}
                disabled={savingBounty}
                className="px-3 py-1.5 rounded-lg bg-accent/20 border border-accent/40 text-accent font-black text-[9px] uppercase tracking-widest hover:bg-accent/30 transition-all cursor-pointer disabled:opacity-50"
              >
                {savingBounty ? 'Saving...' : 'Save Details'}
              </button>
            </div>
          </div>
        </div>

        <div className="glass-panel border border-line rounded-xl p-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="text-[10px] font-black uppercase tracking-widest text-muted">POC Report Builder</div>
            <p className="text-[10px] text-muted leading-relaxed">
              Export reproduction packages, evidence lists, and HTTP dumps formatted as bug-bounty markdown reports.
            </p>
            <label className="flex items-center gap-2 text-[10px] text-muted cursor-pointer select-none pt-1">
              <input
                type="checkbox"
                checked={sanitizePII}
                onChange={(e) => onSanitizePIIChange(e.target.checked)}
                className="accent-accent"
              />
              Mask PII (Authorization, Cookies)
            </label>
          </div>
          <div className="flex gap-2 mt-4 pt-3 border-t border-line-muted">
            <button
              type="button"
              onClick={onCopyReport}
              className="flex-1 px-3 py-2 rounded-lg bg-accent text-black font-black text-[10px] uppercase tracking-widest hover:bg-accent-dim transition-all cursor-pointer flex items-center justify-center gap-1 shadow-glow-accent-sm"
            >
              Copy Report (MD)
            </button>
            <Link
              to={`/reports/builder?finding=${finding.id}`}
              className="flex-1 px-3 py-2 rounded-lg bg-surface-hover border border-line text-text-primary font-black text-[10px] uppercase tracking-widest hover:bg-surface-2 transition-all cursor-pointer flex items-center justify-center gap-1"
            >
              Report Bundle
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
