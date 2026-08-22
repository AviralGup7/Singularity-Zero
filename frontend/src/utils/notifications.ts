

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

export function notificationDelivery(permission: string | undefined): { inApp: boolean; push: boolean } {
  return { inApp: true, push: permission === 'granted' };
}

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
    id: `notif-${crypto.randomUUID()}`,
    type,
    title,
    body,
    timestamp: new Date().toISOString(),
    data,
  };

  storeInAppNotification(notification);
  const delivery = notificationDelivery(
    typeof Notification !== 'undefined' ? Notification.permission : undefined,
  );
  if (delivery.inApp) dispatchInAppEvent(notification);

  if (delivery.push && 'Notification' in window) {
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
  }
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

export function parseInAppNotifications(raw: string | null): AppNotification[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed as AppNotification[] : [];
  } catch {
    return [];
  }
}

function dispatchInAppEvent(notification: AppNotification): void {
  window.dispatchEvent(
    new CustomEvent('app-notification', { detail: notification })
  );
}


