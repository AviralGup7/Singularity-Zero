export function unreadAfterMarkRead(wasUnread: boolean, current: number): number {
  if (!wasUnread) return Math.max(0, current);
  return Math.max(0, current - 1);
}

export function unreadAfterDismiss(wasUnread: boolean, current: number): number {
  return unreadAfterMarkRead(wasUnread, current);
}

export function visibleFindingIds(allIds: string[], pendingNewIds: string[]): string[] {
  if (pendingNewIds.length === 0) return allIds;
  const hide = new Set(pendingNewIds);
  return allIds.filter((id) => !hide.has(id));
}

export function applyMarkRead<T extends { id: string; read?: boolean }>(
  items: T[],
  id: string,
): { items: T[]; wasUnread: boolean } {
  let wasUnread = false;
  const next = items.map((item) => {
    if (item.id !== id) return item;
    if (!item.read) wasUnread = true;
    return { ...item, read: true };
  });
  return { items: next, wasUnread };
}

export function applyDismiss<T extends { id: string; read?: boolean }>(
  items: T[],
  id: string,
): { items: T[]; wasUnread: boolean } {
  const target = items.find((item) => item.id === id);
  return {
    items: items.filter((item) => item.id !== id),
    wasUnread: Boolean(target && !target.read),
  };
}
