export type ReconSection = 'subdomains' | 'urls' | 'parameters';

export function nextExpandedSections(
  current: Iterable<string>,
  section: string,
  open: boolean,
): Set<string> {
  const next = new Set(current);
  if (open) next.add(section);
  else next.delete(section);
  return next;
}
