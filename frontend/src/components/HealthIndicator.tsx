import { useState, useEffect } from 'react';
import { getHealth } from '../api/client';
import type { HealthStatus } from '@/types/api';

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
      <div className="text-xs text-bad" role="status" aria-label="Backend is offline">
        <span aria-hidden="true">!</span>
        <span>Backend Offline</span>
      </div>
    );
  }

  if (!health) return null;

  return (
    <div className="text-xs text-ok" role="status" aria-label="Backend is online">
      <span aria-hidden="true">✅</span>
      <span>Backend Online</span>
    </div>
  );
}
