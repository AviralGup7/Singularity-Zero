/** Hook for managing notifications with server-side persistence + SSE streaming.

Provides:
  - Fetching notifications from /api/notifications
  - Subscribing to real-time SSE stream at /api/notifications/stream
  - Mark read / mark all read / delete operations
  - Local state management synced with server
*/

import { useState, useEffect, useCallback, useRef } from 'react';
import { useMountedRef } from './realtime/shared';
import type {
  AppNotification,
  NotificationSSEEvent,
  NotificationListResponse,
} from '@/types/notifications';
import { sseEventToAppNotification, apiNotificationToAppNotification } from '@/types/notifications';
import { getStreamToken } from '@/api/streamAuth';
import {
  inboxWriteBase,
  notificationsFetchUrl,
  notificationsStreamUrl,
  unwrapEnvelope,
} from '@/features/bridge/demoChannel';
import { shouldFetchNotifications, shouldOpenNotificationStream } from '@/features/notifications/policy';
import { useAuthStore } from '@/stores/authStore';
import { showErrorToast } from '@/utils/extractErrorMessage';
import { applyDismiss, applyMarkRead, unreadAfterDismiss, unreadAfterMarkRead } from '@/features/notifications/unread';

function consoleGate() {
  const token = getStreamToken();
  const user = useAuthStore.getState().user;
  const session = user
    ? {
        kind: (token ? 'jwt' : 'demo') as 'jwt' | 'demo',
        subject: user.name,
        role: String(user.role),
        capabilities: [] as string[],
        has_bearer_token: Boolean(token),
      }
    : null;
  return { token, session };
}

const POLL_INTERVAL_MS = 30000;

interface UseNotificationsReturn {
  notifications: AppNotification[];
  unreadCount: number;
  loading: boolean;
  markRead: (id: string) => Promise<void>;
  markAllRead: () => Promise<void>;
  dismiss: (id: string) => Promise<void>;
  clearAll: () => Promise<void>;
  refresh: () => Promise<void>;
}

function isBenignBackendMiss(status?: number, err?: unknown): boolean {
  if (status === 401 || status === 403 || status === 404 || (typeof status === 'number' && status >= 500)) {
    return true;
  }
  const msg = err instanceof Error ? err.message : String(err ?? '');
  return /401|403|unauthorized|failed to fetch|networkerror|502|503|504|econnrefused/i.test(msg);
}

export function useNotifications(enabled = true): UseNotificationsReturn {
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const { mountedRef } = useMountedRef();
  const eventSourceRef = useRef<EventSource | null>(null);
  const seenIdsRef = useRef<Set<string>>(new Set());
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const notificationsRef = useRef<AppNotification[]>([]);
  notificationsRef.current = notifications;

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  const fetchNotifications = useCallback(async () => {
    try {
      const { token, session } = consoleGate();
      const url = notificationsFetchUrl({ session, bearerToken: token });
      if (!url) {
        if (mountedRef.current) setLoading(false);
        return;
      }
      const headers: Record<string, string> = {};
      if (shouldFetchNotifications(token)) {
        headers.Authorization = `Bearer ${token}`;
      }
      if (session?.subject) {
        headers['X-Console-Subject'] = session.subject;
      }

      const res = await fetch(url, { headers });
      if (!res.ok) {
        if (!isBenignBackendMiss(res.status)) {
          showErrorToast(new Error(`Notifications request failed (${res.status})`), 'Failed to load notifications');
        }
        return;
      }

      const data = unwrapEnvelope<NotificationListResponse>(await res.json());
      if (!mountedRef.current) return;
      if (!Array.isArray(data.notifications)) return;

      const appNotifs = data.notifications.map(apiNotificationToAppNotification);
      notificationsRef.current = appNotifs;
      setNotifications(appNotifs);
      setUnreadCount(data.unread_count);

      // Track seen IDs for dedup
      seenIdsRef.current.clear();
      for (const n of appNotifs) {
        seenIdsRef.current.add(n.id);
      }
    } catch (err) {
      if (!isBenignBackendMiss(undefined, err)) {
        showErrorToast(err, 'Failed to fetch notifications');
      }
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [mountedRef]);

  const startPolling = useCallback(() => {
    if (pollingRef.current) return;
    pollingRef.current = setInterval(() => {
      if (mountedRef.current) {
        fetchNotifications();
      }
    }, POLL_INTERVAL_MS);
  }, [fetchNotifications, mountedRef]);

  const connectSSE = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const { token, session } = consoleGate();
    const streamUrl = notificationsStreamUrl({ session, bearerToken: token });
    if (!streamUrl || !shouldOpenNotificationStream(token)) return;

    const sseUrl = streamUrl;
    const es = new EventSource(sseUrl);
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      if (!mountedRef.current) return;
      try {
        const data = JSON.parse(event.data) as NotificationSSEEvent;

        // Skip heartbeats
        if (data.type === ('heartbeat' as string)) return;

        // Dedup by ID
        if (data.id && seenIdsRef.current.has(data.id)) return;
        if (data.id) seenIdsRef.current.add(data.id);

        const notif = sseEventToAppNotification(data);

        setNotifications((prev) => {
          const next = [notif, ...prev].slice(0, 200);
          notificationsRef.current = next;
          return next;
        });
        if (!notif.read) {
          setUnreadCount((c) => c + 1);
        }
      } catch {
        // Non-JSON message, ignore
      }
    };

    es.onerror = () => {
      // SSE will auto-reconnect. If it fails permanently, fall back to polling.
      if (es.readyState === EventSource.CLOSED) {
        startPolling();
      }
    };
  }, [mountedRef, startPolling]);

  const markRead = useCallback(async (id: string) => {
    const next = applyMarkRead(notificationsRef.current, id);
    notificationsRef.current = next.items;
    setNotifications(next.items);
    setUnreadCount((c) => unreadAfterMarkRead(next.wasUnread, c));

    try {
      const { token, session } = consoleGate();
      const base = inboxWriteBase({ session, bearerToken: token });
      if (!base) return;
      const headers: Record<string, string> = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      if (session?.subject) headers['X-Console-Subject'] = session.subject;

      const res = await fetch(`${base}/${id}/read`, {
        method: 'PATCH',
        headers,
      });
      if (res.ok) {
        const data = await res.json() as { unread_count: number };
        setUnreadCount(data.unread_count);
      }
    } catch (err) {
      showErrorToast(err, 'Failed to mark notification as read');
      fetchNotifications();
    }
  }, [fetchNotifications]);

  const markAllRead = useCallback(async () => {
    // Optimistic update
    setNotifications((prev) => {
      const next = prev.map((n) => ({ ...n, read: true }));
      notificationsRef.current = next;
      return next;
    });
    setUnreadCount(0);

    try {
      const { token, session } = consoleGate();
      const base = inboxWriteBase({ session, bearerToken: token });
      if (!base) return;
      const headers: Record<string, string> = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      if (session?.subject) headers['X-Console-Subject'] = session.subject;

      const res = await fetch(`${base}/read-all`, {
        method: 'PATCH',
        headers,
      });
      if (res.ok) {
        const data = await res.json() as { unread_count: number };
        setUnreadCount(data.unread_count);
      }
    } catch (err) {
      showErrorToast(err, 'Failed to mark all notifications as read');
      fetchNotifications();
    }
  }, [fetchNotifications]);

  const dismiss = useCallback(async (id: string) => {
    const next = applyDismiss(notificationsRef.current, id);
    notificationsRef.current = next.items;
    setNotifications(next.items);
    setUnreadCount((count) => unreadAfterDismiss(next.wasUnread, count));

    try {
      const { token, session } = consoleGate();
      const base = inboxWriteBase({ session, bearerToken: token });
      if (!base) return;
      const headers: Record<string, string> = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      if (session?.subject) headers['X-Console-Subject'] = session.subject;

      await fetch(`${base}/${id}`, { method: 'DELETE', headers });
      const remaining = notificationsRef.current;
      setUnreadCount(remaining.filter((n) => !n.read).length);
    } catch (err) {
      showErrorToast(err, 'Failed to dismiss notification');
      fetchNotifications();
    }
  }, [fetchNotifications]);

  const clearAll = useCallback(async () => {
    setNotifications([]);
    setUnreadCount(0);

    try {
      const { token, session } = consoleGate();
      const base = inboxWriteBase({ session, bearerToken: token });
      if (!base) return;
      const headers: Record<string, string> = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      if (session?.subject) headers['X-Console-Subject'] = session.subject;

      await fetch(base, { method: 'DELETE', headers });
    } catch (err) {
      showErrorToast(err, 'Failed to clear all notifications');
      fetchNotifications();
    }
  }, [fetchNotifications]);

  // Initial fetch + SSE connection (defer fetch to avoid competing with paint)
  useEffect(() => {
    mountedRef.current = true;
    if (!enabled) {
      setLoading(false);
      return () => {
        mountedRef.current = false;
      };
    }
    const defer = typeof window.requestIdleCallback === 'function'
      ? (fn: () => void) => requestIdleCallback(() => fn(), { timeout: 2000 })
      : (fn: () => void) => setTimeout(fn, 0);
    defer(() => fetchNotifications());
    connectSSE();

    return () => {
      mountedRef.current = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      stopPolling();
    };
  }, [enabled, fetchNotifications, connectSSE, stopPolling, mountedRef]);

  return {
    notifications,
    unreadCount,
    loading,
    markRead,
    markAllRead,
    dismiss,
    clearAll,
    refresh: fetchNotifications,
  };
}
