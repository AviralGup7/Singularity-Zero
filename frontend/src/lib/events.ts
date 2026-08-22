export type AppEventType = 'notification:add' | 'app:refresh';

export interface NotificationPayload {
  message: string;
  type: string;
}

export type AppEventMap = {
  'notification:add': CustomEvent<NotificationPayload>;
};

export function emitNotification(payload: NotificationPayload) {
  const message = typeof payload?.message === 'string' ? payload.message : '';
  const type = typeof payload?.type === 'string' ? payload.type : 'info';
  window.dispatchEvent(new CustomEvent<NotificationPayload>('notification:add', {
    detail: { message, type },
  }));
}

export function emitRefresh() {
  window.dispatchEvent(new CustomEvent('app:refresh'));
}

export function onRefresh(handler: () => void) {
  window.addEventListener('app:refresh', handler);
  return () => window.removeEventListener('app:refresh', handler);
}

export function onNotification(handler: (payload: NotificationPayload) => void) {
  const listener = (e: Event) => {
    handler((e as CustomEvent<NotificationPayload>).detail);
  };
  window.addEventListener('notification:add', listener);
  return () => window.removeEventListener('notification:add', listener);
}
