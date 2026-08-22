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
