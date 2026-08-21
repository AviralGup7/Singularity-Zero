import { JWT_NOTIFICATION_PATHS } from './commands';
import { shouldCallJwtNotifications, shouldUseConsoleInbox, type GateInput } from './authGate';
import type { TransportHints } from './types';

export function transportHints(input: GateInput): TransportHints {
  const jwtOk = shouldCallJwtNotifications(input);
  const demo = Boolean(input.session && (input.session.kind === 'demo' || input.session.kind === 'guest'));
  return {
    use_console_channel: true,
    skip_jwt_notifications: !jwtOk,
    skip_jwt_notification_stream: !jwtOk,
    demo_or_guest: demo,
    has_bearer_token: jwtOk,
    fetch_notifications_http: jwtOk,
    open_notification_stream: jwtOk,
    use_console_inbox: shouldUseConsoleInbox(input),
    reason: demo ? 'demo_or_guest' : jwtOk ? 'bearer' : 'anonymous',
  };
}

export function shouldFetchPath(path: string, input: GateInput): boolean {
  const normalized = path.split('?')[0] ?? path;
  const jwtInbox = JWT_NOTIFICATION_PATHS.some(
    (prefix) => normalized === prefix || normalized.startsWith('/api/notifications/'),
  );
  if (jwtInbox) {
    return shouldCallJwtNotifications(input);
  }
  return true;
}

/**
 * Wrap existing notification hooks: skip the JWT URL after Demo Sign In
 * so the UI does not spam 401.
 */
export function notificationsFetchUrl(input: GateInput): string | null {
  if (shouldCallJwtNotifications(input)) {
    return '/api/notifications?limit=100&offset=0';
  }
  if (shouldUseConsoleInbox(input)) {
    return '/api/console/notifications';
  }
  return null;
}

export function notificationsStreamUrl(input: GateInput): string | null {
  if (shouldCallJwtNotifications(input) && input.bearerToken) {
    return `/api/notifications/stream?token=${encodeURIComponent(input.bearerToken)}`;
  }
  if (shouldUseConsoleInbox(input)) {
    return '/api/console/stream';
  }
  return null;
}

export function inboxWriteBase(input: GateInput): string | null {
  if (shouldCallJwtNotifications(input)) {
    return '/api/notifications';
  }
  if (shouldUseConsoleInbox(input)) {
    return '/api/console/notifications';
  }
  return null;
}

export function unwrapEnvelope<T extends Record<string, unknown>>(json: unknown): T {
  if (!json || typeof json !== 'object') {
    return {} as T;
  }
  const record = json as Record<string, unknown>;
  if (record.notifications || record.unread_count !== undefined) {
    return record as T;
  }
  if (record.data && typeof record.data === 'object') {
    return record.data as T;
  }
  return record as T;
}
