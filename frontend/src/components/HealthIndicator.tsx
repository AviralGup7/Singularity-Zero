import { useHealthStatus } from '@/hooks/useHealthStatus';

export default function HealthIndicator() {
  const { ready, status, degradedReasons, loading, error } = useHealthStatus();

  if (loading) return null;

  if (error) {
    return (
      <div className="flex items-center gap-2 text-xs text-bad" role="status" aria-label="Backend is offline">
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--bad)', boxShadow: 'var(--glow-bad)', display: 'inline-block' }} aria-hidden="true" />
        <span>Backend Offline</span>
      </div>
    );
  }

  if (!ready || status === 'degraded') {
    const reason = degradedReasons.length > 0 ? degradedReasons[0] : 'Some subsystems unavailable';
    return (
      <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--warning-text, #eab308)' }} role="status" aria-label="Backend is degraded">
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--warning, #eab308)', display: 'inline-block' }} aria-hidden="true" />
        <span>Degraded</span>
        <span className="text-[var(--text-tertiary)]" title={reason}>· {reason}</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 text-xs text-ok" role="status" aria-label="Backend is online">
      <span className="pulse-dot" aria-hidden="true" />
      <span>Online</span>
    </div>
  );
}
