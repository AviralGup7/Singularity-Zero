export type AppEventType = 'notification:add' | 'search:items-update' | 'app:refresh';

export interface NotificationPayload {
  message: string;
  type: string;
}

export interface SearchItemsPayload {
  items: unknown[];
}

export type AppEventMap = {
  'notification:add': CustomEvent<NotificationPayload>;
  'search:items-update': CustomEvent<SearchItemsPayload>;
};

export function emitNotification(payload: NotificationPayload) {
  window.dispatchEvent(new CustomEvent<NotificationPayload>('notification:add', { detail: payload }));
}

export function emitSearchItems(payload: SearchItemsPayload) {
  window.dispatchEvent(new CustomEvent<SearchItemsPayload>('search:items-update', { detail: payload }));
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

export function onSearchItems(handler: (payload: SearchItemsPayload) => void) {
  const listener = (e: Event) => {
    handler((e as CustomEvent<SearchItemsPayload>).detail);
  };
  window.addEventListener('search:items-update', listener);
  return () => window.removeEventListener('search:items-update', listener);
}
