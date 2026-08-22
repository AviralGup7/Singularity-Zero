import { useCallback, useMemo, useRef, useState } from 'react';

import { ConsoleClient } from '@/features/bridge/client';
import { ConsoleConnection } from '@/features/bridge/connection';
import { notificationsFetchUrl, transportHints } from '@/features/bridge/demoChannel';
import type { ConsoleSession, JobCard, NotificationCard, TransportHints } from '@/features/bridge/types';

interface BridgeState {
  session: ConsoleSession | null;
  connectionId: string | null;
  transport: TransportHints | null;
  jobs: JobCard[];
  notifications: NotificationCard[];
  error: string | null;
}

export function isUsableOperatorName(name: string): boolean {
  return name.trim().length > 0;
}

export function isUsableScanUrl(url: string): boolean {
  return url.trim().length > 0;
}

const empty: BridgeState = {
  session: null,
  connectionId: null,
  transport: null,
  jobs: [],
  notifications: [],
  error: null,
};

export function useConsoleBridge() {
  const [state, setState] = useState<BridgeState>(empty);
  const sessionRef = useRef<ConsoleSession | null>(null);
  const connectionRef = useRef<string | null>(null);

  const client = useMemo(
    () =>
      new ConsoleClient({
        getSession: () => sessionRef.current,
        getSubject: () => sessionRef.current?.subject ?? null,
        getConnectionId: () => connectionRef.current,
      }),
    [],
  );

  const connection = useMemo(() => new ConsoleConnection(client), [client]);

  const demoSignIn = useCallback(
    async (name: string, role = 'analyst') => {
      if (!isUsableOperatorName(name)) {
        setState((prev) => ({ ...prev, error: 'Name is required' }));
        throw new Error('Name is required');
      }
      const result = await connection.open(name, role);
      sessionRef.current = result.session;
      connectionRef.current = result.connectionId;
      setState((prev) => ({
        ...prev,
        session: result.session,
        connectionId: result.connectionId,
        transport: result.transport,
        error: null,
      }));
      return result;
    },
    [connection],
  );

  const refreshJobs = useCallback(async () => {
    const response = await client.call<{ jobs?: JobCard[] }>('jobs.list');
    if (response.ok) {
      setState((prev) => ({ ...prev, jobs: response.data.jobs ?? [] }));
    } else {
      setState((prev) => ({ ...prev, error: response.error?.message ?? 'jobs.list failed' }));
    }
  }, [client]);

  const refreshInbox = useCallback(async () => {
    const hints = transportHints({
      session: sessionRef.current,
      bearerToken: sessionRef.current?.has_bearer_token ? 'present' : null,
    });
    if (!hints.use_console_inbox && !hints.fetch_notifications_http) {
      return;
    }
    const url = notificationsFetchUrl({ session: sessionRef.current });
    if (!url) return;
    const response = await client.call<{ notifications?: NotificationCard[] }>('notifications.list');
    if (response.ok) {
      setState((prev) => ({ ...prev, notifications: response.data.notifications ?? [] }));
    }
  }, [client]);

  const startScan = useCallback(
    async (baseUrl: string) => {
      if (!isUsableScanUrl(baseUrl)) {
        setState((prev) => ({ ...prev, error: 'Target URL is required' }));
        return null;
      }
      const response = await client.call<{ job?: JobCard }>('jobs.start', { base_url: baseUrl });
      if (!response.ok) {
        setState((prev) => ({ ...prev, error: response.error?.message ?? 'jobs.start failed' }));
        return null;
      }
      await refreshJobs();
      await refreshInbox();
      return response.data.job ?? null;
    },
    [client, refreshInbox, refreshJobs],
  );

  return {
    ...state,
    demoSignIn,
    refreshJobs,
    refreshInbox,
    startScan,
    client,
  };
}
