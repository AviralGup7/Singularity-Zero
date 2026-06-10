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

export function useNotifications(): UseNotificationsReturn {
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const { mountedRef } = useMountedRef();
  const eventSourceRef = useRef<EventSource | null>(null);
  const seenIdsRef = useRef<Set<string>>(new Set());
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const API_BASE = '/api/notifications';

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  const fetchNotifications = useCallback(async () => {
    try {
      const token = getStreamToken();
      const url = `${API_BASE}?limit=100&offset=0`;
      const headers: Record<string, string> = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const res = await fetch(url, { headers });
      if (!res.ok) return;

      const data: NotificationListResponse = await res.json();
      if (!mountedRef.current) return;

      const appNotifs = data.notifications.map(apiNotificationToAppNotification);
      setNotifications(appNotifs);
      setUnreadCount(data.unread_count);

      // Track seen IDs for dedup
      seenIdsRef.current.clear();
      for (const n of appNotifs) {
        seenIdsRef.current.add(n.id);
      }
    } catch (err) {
      console.warn('Failed to fetch notifications:', err);
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

    const token = getStreamToken();
    let sseUrl = `${API_BASE}/stream`;
    if (token) {
      sseUrl += `?token=${encodeURIComponent(token)}`;
    }

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

        setNotifications((prev) => [notif, ...prev].slice(0, 200));
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
    // Optimistic update
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
    setUnreadCount((c) => Math.max(0, c - 1));

    try {
      const token = getStreamToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`${API_BASE}/${id}/read`, {
        method: 'PATCH',
        headers,
      });
      if (res.ok) {
        const data = await res.json() as { unread_count: number };
        setUnreadCount(data.unread_count);
      }
    } catch {
      // Revert on failure
      fetchNotifications();
    }
  }, [fetchNotifications]);

  const markAllRead = useCallback(async () => {
    // Optimistic update
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    setUnreadCount(0);

    try {
      const token = getStreamToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`${API_BASE}/read-all`, {
        method: 'PATCH',
        headers,
      });
      if (res.ok) {
        const data = await res.json() as { unread_count: number };
        setUnreadCount(data.unread_count);
      }
    } catch {
      fetchNotifications();
    }
  }, [fetchNotifications]);

  const dismiss = useCallback(async (id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));

    try {
      const token = getStreamToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      await fetch(`${API_BASE}/${id}`, { method: 'DELETE', headers });
      // Update unread count
      setNotifications((prev) => {
        setUnreadCount(prev.filter((n) => !n.read).length);
        return prev;
      });
    } catch {
      fetchNotifications();
    }
  }, [fetchNotifications]);

  const clearAll = useCallback(async () => {
    setNotifications([]);
    setUnreadCount(0);

    try {
      const token = getStreamToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      await fetch(API_BASE, { method: 'DELETE', headers });
    } catch {
      fetchNotifications();
    }
  }, [fetchNotifications]);

  // Initial fetch + SSE connection
  useEffect(() => {
    mountedRef.current = true;
    fetchNotifications();
    connectSSE();

    return () => {
      mountedRef.current = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      stopPolling();
    };
  }, [fetchNotifications, connectSSE, stopPolling, mountedRef]);

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
