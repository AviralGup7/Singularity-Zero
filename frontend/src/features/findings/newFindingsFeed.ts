export function acknowledgeNewFindings(seen: Iterable<string>, incoming: Iterable<string>): string[] {
  return Array.from(new Set([...seen, ...incoming]));
}

export function detectFreshFindingIds(seen: Iterable<string>, current: Iterable<string>): string[] {
  const known = new Set(seen);
  return Array.from(current).filter((id) => Boolean(id) && !known.has(id));
}

/** Drop the deep-link `finding` query so closing the detail pane cannot reopen it. */
export function withoutFindingParam(search: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams(search);
  next.delete('finding');
  return next;
}
