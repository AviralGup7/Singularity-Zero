import { GitBranch } from 'lucide-react';
import type { Finding } from '@/types/api';
import { FindingReviewPanel } from '@/components/findings/FindingReviewPanel';

interface FindingRiskPanelProps {
  finding: Finding;
  reviewerId: string;
}

export function FindingRiskPanel({ finding, reviewerId }: FindingRiskPanelProps) {
  return (
    <div className="space-y-6" data-testid="finding-risk-panel">
      {/* Modern risk composite score */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="glass-panel border border-white/5 rounded-xl p-4">
          <div className="text-[10px] font-black uppercase tracking-widest text-muted mb-1">Modern risk</div>
          <div className="text-2xl font-black text-text">
            {(finding.modern_risk_score ?? 0).toFixed(1)}
          </div>
          <div className="text-[10px] font-mono text-muted">/ 100</div>
        </div>
        <div className="glass-panel border border-white/5 rounded-xl p-4">
          <div className="text-[10px] font-black uppercase tracking-widest text-muted mb-1">Remediation priority</div>
          <div className="text-2xl font-black text-accent">
            {(finding.remediation_priority ?? 0).toFixed(1)}
          </div>
          <div className="text-[10px] font-mono text-muted">/ 100</div>
        </div>
        <div className="glass-panel border border-white/5 rounded-xl p-4">
          <div className="text-[10px] font-black uppercase tracking-widest text-muted mb-1">CVSS v4</div>
          <div className="text-2xl font-black text-text">
            {(finding.cvss_v4_score ?? finding.cvss_score ?? 0).toFixed(1)}
          </div>
          <div className="text-[10px] font-mono text-muted">/ 10</div>
        </div>
      </div>

      {/* Threat intel */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="glass-panel border border-white/5 rounded-xl p-3">
          <div className="text-[10px] font-black uppercase tracking-widest text-muted">EPSS</div>
          <div className="text-sm font-mono text-text">
            {((finding.threat_intel?.epss_score ?? finding.epss_score ?? 0) * 100).toFixed(1)}%
          </div>
        </div>
        <div className="glass-panel border border-white/5 rounded-xl p-3">
          <div className="text-[10px] font-black uppercase tracking-widest text-muted">CISA KEV</div>
          <div className="text-sm font-mono text-text">
            {(finding.threat_intel?.cisa_kev ?? finding.cisa_kev) ? (
              <span className="text-red-500 font-bold">LISTED</span>
            ) : (
              <span className="text-muted">—</span>
            )}
          </div>
        </div>
        <div className="glass-panel border border-white/5 rounded-xl p-3">
          <div className="text-[10px] font-black uppercase tracking-widest text-muted">Asset type</div>
          <div className="text-sm font-mono text-text">
            {finding.asset_type ?? '—'}
          </div>
        </div>
        <div className="glass-panel border border-white/5 rounded-xl p-3">
          <div className="text-[10px] font-black uppercase tracking-widest text-muted">Control discount</div>
          <div className="text-sm font-mono text-text">
            {finding.control_discount != null
              ? `${((1 - finding.control_discount) * 100).toFixed(0)}%`
              : '—'}
          </div>
        </div>
      </div>

      {/* Reason codes */}
      {finding.remediation_priority_reasons && finding.remediation_priority_reasons.length > 0 && (
        <div className="glass-panel border border-white/5 rounded-xl p-3">
          <div className="text-[10px] font-black uppercase tracking-widest text-muted mb-2">
            Why this is prioritised
          </div>
          <div className="flex flex-wrap gap-2">
            {finding.remediation_priority_reasons.map((code) => (
              <span
                key={code}
                className="text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded bg-accent/15 text-accent border border-accent/30"
              >
                {code}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Attack chain membership surface */}
      {finding.attack_chain && (
        <div className="glass-panel border border-white/5 rounded-xl p-3">
          <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-muted mb-2">
            <GitBranch size={12} /> Attack Chain Membership
          </div>
          <div className="text-[11px] font-mono text-text space-y-1">
            <div>
              <span className="text-muted">chain_id:</span> {finding.attack_chain.chain_id ?? '—'}
            </div>
            <div>
              <span className="text-muted">chain_kind:</span> {finding.attack_chain.chain_kind ?? '—'}
            </div>
            <div>
              <span className="text-muted">amplification:</span>{' '}
              {finding.attack_chain.chain_amplification?.toFixed(2) ?? '—'}x
            </div>
            <div>
              <span className="text-muted">chain_size:</span> {finding.attack_chain.chain_size ?? '—'}
            </div>
          </div>
        </div>
      )}

      {/* Lifecycle SLA */}
      <div className="glass-panel border border-white/5 rounded-xl p-3">
        <div className="text-[10px] font-black uppercase tracking-widest text-muted mb-2">Lifecycle</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[10px] font-mono text-text">
          {(
            [
              ['Triaged', finding.triaged_at],
              ['In Remediation', finding.remediation_started_at],
              ['Fixed', finding.fixed_at],
              ['Verified', finding.verified_at],
            ] as Array<[string, string | number | undefined]>
          ).map(([label, value]) => (
            <div key={label}>
              <div className="text-muted uppercase tracking-widest">{label}</div>
              <div>{value ? new Date(value).toISOString().slice(0, 10) : '—'}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Analyst review panel */}
      <FindingReviewPanel
        findingId={finding.id}
        defaultReviewer={reviewerId}
      />
    </div>
  );
}
