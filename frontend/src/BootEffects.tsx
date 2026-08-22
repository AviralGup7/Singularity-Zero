import { useEffect } from 'react';
import { getLiveness } from '@/api/health';
import { syncServerTime } from '@/lib/timeSync';
import { errorTracker } from '@/utils/errorTracker';
import { useAuthStore } from '@/stores/authStore';
import { useEventLogStore } from '@/stores/eventLogStore';

export function BootEffects() {
  useEffect(() => {
    getLiveness()
      .then(res => {
        if (res.timestamp) syncServerTime(res.timestamp);
      })
      .catch(err => {
        errorTracker.track(err, { component: 'App', action: 'telemetry-sync' });
        console.warn('[SYSTEM] Initial telemetry sync failed. Backend may be offline.');
      });

    try {
      const result = useAuthStore.getState().hydrateAuth() as unknown;
      if (result && typeof (result as Promise<unknown>).then === 'function') {
        void (result as Promise<unknown>).catch((err: unknown) => {
          errorTracker.track(err instanceof Error ? err : new Error(String(err)), {
            component: 'BootEffects',
            action: 'hydrateAuth',
          });
        });
      }
    } catch (err) {
      errorTracker.track(err instanceof Error ? err : new Error(String(err)), {
        component: 'BootEffects',
        action: 'hydrateAuth',
      });
    }

    const interval = setInterval(() => {
      try {
        useEventLogStore.getState().prune();
      } catch (err) {
        errorTracker.track(err instanceof Error ? err : new Error(String(err)), {
          component: 'BootEffects',
          action: 'pruneEventLog',
        });
      }
    }, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  return null;
}
