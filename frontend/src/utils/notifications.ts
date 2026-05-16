import { useEffect, useRef } from 'react';

export type NotificationType = 'scan-complete' | 'critical-finding' | 'sla-breach' | 'info';

export interface AppNotification {
  id: string;
  type: NotificationType;
  title: string;
  body: string;
  timestamp: string;
  data?: Record<string, unknown>;
}

const NOTIFICATION_STORAGE_KEY = 'cyber-pipeline-notifications';

export async function requestNotificationPermission(): Promise<NotificationPermission> {
  if (!('Notification' in window)) {
    console.warn('Browser does not support notifications');
    return 'denied';
  }
  return Notification.requestPermission();
}

export function sendPushNotification(
  type: NotificationType,
  title: string,
  body: string,
  data?: Record<string, unknown>
): void {
  const notification: AppNotification = {
    id: `notif-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type,
    title,
    body,
    timestamp: new Date().toISOString(),
    data,
  };

  storeInAppNotification(notification);

  if ('Notification' in window && Notification.permission === 'granted') {
    try {
      new Notification(title, {
        body,
        icon: '/favicon.svg',
        tag: notification.id,
        requireInteraction: type === 'critical-finding' || type === 'sla-breach',
      });
    } catch (e) {
      console.warn('Failed to send push notification:', e);
    }
  } else {
    // FIX: Uncommented dispatchInAppEvent so in-app listeners receive notifications
    dispatchInAppEvent(notification);
  }
}

export function sendScanCompleteNotification(jobId: string, jobName: string): void {
  sendPushNotification(
    'scan-complete',
    'Scan Complete',
    `Job "${jobName}" (${jobId}) has finished.`,
    { jobId, jobName }
  );
}

export function sendCriticalFindingNotification(findingId: string, severity: string): void {
  sendPushNotification(
    'critical-finding',
    'Critical Finding Detected',
    `A ${severity} severity finding (${findingId}) requires immediate attention.`,
    { findingId, severity }
  );
}

export function sendSLABreachNotification(slaId: string, metric: string): void {
  sendPushNotification(
    'sla-breach',
    'SLA Breach',
    `SLA metric "${metric}" (${slaId}) has been breached.`,
    { slaId, metric }
  );
}

function storeInAppNotification(notification: AppNotification): void {
  try {
    const raw = localStorage.getItem(NOTIFICATION_STORAGE_KEY);
   
    const all: AppNotification[] = raw ? JSON.parse(raw) : [];
    all.unshift(notification);
    if (all.length > 100) all.length = 100;
    localStorage.setItem(NOTIFICATION_STORAGE_KEY, JSON.stringify(all));
  } catch (e) {
    console.warn('Failed to store notification:', e);
  }
}

export function getInAppNotifications(): AppNotification[] {
  try {
    const raw = localStorage.getItem(NOTIFICATION_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function clearInAppNotifications(): void {
  localStorage.removeItem(NOTIFICATION_STORAGE_KEY);
}

function dispatchInAppEvent(notification: AppNotification): void {
  window.dispatchEvent(
    new CustomEvent('app-notification', { detail: notification })
  );
}

// FIX: Convert to proper hook with ref to avoid stale closure
export function useNotificationListener(callback: (notification: AppNotification) => void) {
  const callbackRef = useRef(callback);

  useEffect(() => {
    callbackRef.current = callback;
   
  }, [callback]);

  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail as AppNotification;
      callbackRef.current(detail);
    };

    window.addEventListener('app-notification', handler);
    return () => window.removeEventListener('app-notification', handler);
  }, []);
}
