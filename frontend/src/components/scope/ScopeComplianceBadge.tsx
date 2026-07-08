import { useMemo } from 'react';
import { CheckCircle2, XCircle, HelpCircle, AlertTriangle } from 'lucide-react';
import { StatusBadge } from '@/components/common/StatusBadge';
import { useScopeStore } from '@/stores/scopeStore';
import { classifyAgainstScope } from '@/utils/scopeParser';
import type { ScopeStatus } from '@/utils/scopeParser';

interface ScopeComplianceBadgeProps {
  asset: string;
  statusOverride?: ScopeStatus;
  iconOnly?: boolean;
  className?: string;
}

const STATUS_META: Record<ScopeStatus, { label: string; description: string; status: 'success' | 'danger' | 'neutral' }> = {
  in_scope: { label: 'In scope', description: 'Asset matches an in-scope entry', status: 'success' },
  out_of_scope: { label: 'Out of scope', description: 'Asset matches an out-of-scope entry', status: 'danger' },
  unknown: { label: 'No scope data', description: 'Not covered by imported policy', status: 'neutral' },
};

export function ScopeComplianceBadge({ asset, statusOverride, iconOnly, className }: ScopeComplianceBadgeProps) {
  const parsed = useScopeStore((s) => s.parsed);
  const classification = useMemo(() => {
    if (statusOverride) return { status: statusOverride as ScopeStatus };
    return classifyAgainstScope(asset, parsed);
  }, [asset, parsed, statusOverride]);

  if (!asset) return null;
  if (!parsed && !statusOverride) return null;

  const meta = STATUS_META[classification.status];

  return (
    <StatusBadge
      status={meta.status}
      label={iconOnly ? undefined : meta.label}
      showDot={false}
      className={className}
      title={meta.description}
      data-testid="scope-compliance-badge"
      data-scope-status={classification.status}
    >
      {meta.status === 'success' ? <CheckCircle2 size={11} /> : meta.status === 'danger' ? <XCircle size={11} /> : <HelpCircle size={11} />}
      {iconOnly && <span className="sr-only">{meta.label}</span>}
    </StatusBadge>
  );
}

export function ScopeWarningBanner({ asset }: { asset: string }) {
  const parsed = useScopeStore((s) => s.parsed);
  const classification = useMemo(() => classifyAgainstScope(asset, parsed), [asset, parsed]);
  if (!parsed || classification.status !== 'out_of_scope') return null;
  return (
    <div className="banner warning scope-warning-banner" role="alert">
      <AlertTriangle size={14} />
      <span>
        <strong>{asset}</strong> matches an <em>out-of-scope</em> asset in the imported program policy. Confirm with the
        program before launching a 12-hour scan.
      </span>
    </div>
  );
}
