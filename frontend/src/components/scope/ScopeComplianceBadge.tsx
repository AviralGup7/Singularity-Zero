import { useMemo } from 'react';
import { CheckCircle2, XCircle, HelpCircle, AlertTriangle } from 'lucide-react';
import { useScopeStore } from '@/stores/scopeStore';
import { classifyAgainstScope } from '@/utils/scopeParser';
import type { ScopeStatus } from '@/utils/scopeParser';

interface ScopeComplianceBadgeProps {
  /**
   * The asset to classify: a hostname, URL, or wildcard pattern.
   */
  asset: string;
  /**
   * Optional explicit override. If provided, the badge shows this status
   * regardless of imported scope.
   */
  statusOverride?: ScopeStatus;
  /**
   * When true, render an icon-only variant. Default false (icon + label).
   */
  iconOnly?: boolean;
  /**
   * Optional className appended to the outer span.
   */
  className?: string;
}

const STATUS_META: Record<ScopeStatus, {
  label: string;
  short: string;
  classes: string;
  Icon: React.ComponentType<{ size?: number; 'aria-hidden'?: boolean | 'true' | 'false' }>;
  description: string;
}> = {
  in_scope: {
    label: 'In scope',
    short: 'IN',
    classes: 'scope-badge--in',
    Icon: CheckCircle2,
    description: 'Asset matches an in-scope entry in the imported program policy',
  },
  out_of_scope: {
    label: 'Out of scope',
    short: 'OUT',
    classes: 'scope-badge--out',
    Icon: XCircle,
    description: 'Asset matches an out-of-scope entry in the imported program policy',
  },
  unknown: {
    label: 'No scope data',
    short: '?',
    classes: 'scope-badge--unknown',
    Icon: HelpCircle,
    description: 'No scope imported yet, or this asset is not covered by the imported policy',
  },
};

export function ScopeComplianceBadge({ asset, statusOverride, iconOnly, className }: ScopeComplianceBadgeProps) {
  const parsed = useScopeStore((s) => s.parsed);
  const classification = useMemo(() => {
    if (statusOverride) return { status: statusOverride as ScopeStatus };
    return classifyAgainstScope(asset, parsed);
  }, [asset, parsed, statusOverride]);

  // Avoid rendering for unparseable / empty assets.
  if (!asset) return null;

  // If the operator hasn't imported a scope, suppress the badge unless
  // explicitly overridden. This prevents a wall of "?" chips before the
  // operator has a chance to import their program.
  if (!parsed && !statusOverride) return null;

  const meta = STATUS_META[classification.status];
  const { Icon } = meta;

  return (
    <span
      className={`scope-badge ${meta.classes} ${className ?? ''}`}
      title={meta.description}
      data-testid="scope-compliance-badge"
      data-scope-status={classification.status}
    >
      <Icon size={iconOnly ? 12 : 11} aria-hidden="true" />
      {!iconOnly && (
        <span className="scope-badge-label">{meta.label}</span>
      )}
    </span>
  );
}

/**
 * Inline alert chip used by the cockpit and the job launcher to surface
 * out-of-scope warnings before a long scan starts.
 */
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
