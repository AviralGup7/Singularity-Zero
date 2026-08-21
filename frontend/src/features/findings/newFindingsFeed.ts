export function acknowledgeNewFindings(seen: Iterable<string>, incoming: Iterable<string>): string[] {
  return Array.from(new Set([...seen, ...incoming]));
}
