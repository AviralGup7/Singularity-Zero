import { useState, useEffect } from 'react';
import { getHealth } from '../api/client';
import type { HealthStatus } from '@/types/api';

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function HealthIndicator() {
   
  const [health, setHealth] = useState<HealthStatus | null>(null);
   
  const [error, setError] = useState(false);

  useEffect(() => {
    const controller = new AbortController();

    async function checkHealth(signal?: AbortSignal) {
      try {
        const data = await getHealth(signal);
        setHealth(data);
        setError(false);
      } catch {
        if (signal?.aborted) return;
        setError(true);
      }
    }
    checkHealth(controller.signal);
    const interval = setInterval(() => checkHealth(controller.signal), 30000);
    return () => {
      controller.abort();
      clearInterval(interval);
    };
  }, []);

  if (error) {
    return (
      <div className="flex items-center gap-2 text-xs text-bad" role="status" aria-label="Backend is offline">
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--bad)', boxShadow: 'var(--glow-bad)', display: 'inline-block' }} aria-hidden="true" />
        <span>Backend Offline</span>
      </div>
    );
  }

  if (!health) return null;

  const rawUptime = health.uptime_seconds ?? (health as unknown as Record<string, unknown>).uptime;
  const uptime = typeof rawUptime === 'number'
    ? formatUptime(rawUptime)
    : null;

  return (
    <div className="flex items-center gap-2 text-xs text-ok" role="status" aria-label="Backend is online">
      <span className="pulse-dot" aria-hidden="true" />
      <span>Online</span>
      {uptime && <span className="text-muted">· {uptime}</span>}
    </div>
  );
}
