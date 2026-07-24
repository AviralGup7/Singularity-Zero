import { useHealthStatus } from '@/hooks/useHealthStatus';

export default function HealthIndicator() {
  const { ready, status, degradedReasons, loading, error } = useHealthStatus();

  if (loading) return null;

  if (error) {
    return (
      <div className="flex items-center gap-2 text-xs text-bad" role="status" aria-live="assertive" aria-label="Backend is offline">
        <span className="inline-block w-2 h-2 rounded-full bg-bad shadow-glow-bad-sm motion-safe:animate-pulse" aria-hidden="true" />
        <span>Backend Offline</span>
      </div>
    );
  }

  if (!ready || status === 'degraded') {
    const reason = degradedReasons.length > 0 ? degradedReasons[0] : 'Some subsystems unavailable';
    return (
      <div className="flex items-center gap-2 text-xs text-warn" role="status" aria-live="polite" aria-label="Backend is degraded">
        <span className="inline-block w-2 h-2 rounded-full bg-warn motion-safe:animate-pulse" aria-hidden="true" />
        <span>Degraded</span>
        <span className="text-text-tertiary truncate max-w-[180px]" title={reason}>· {reason}</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 text-xs text-ok" role="status" aria-live="polite" aria-label="Backend is online">
      <span className="pulse-dot" aria-hidden="true" />
      <span>Online</span>
    </div>
  );
}
