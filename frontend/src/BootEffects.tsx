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
  }, []);

  useEffect(() => {
    useAuthStore.getState().hydrateAuth();
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      useEventLogStore.getState().prune();
    }, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  return null;
}
