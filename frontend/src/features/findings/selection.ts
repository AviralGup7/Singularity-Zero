export function pruneSelection(selected: Iterable<string>, visible: Iterable<string>): string[] {
  const allowed = new Set(visible);
  return Array.from(selected).filter((id) => allowed.has(id));
}

export function pairFromSelection<T extends { id: string }>(
  selected: Iterable<string>,
  items: T[],
): { findingA: T; findingB: T } | null {
  const ids = Array.from(new Set(selected)).filter(Boolean).sort();
  if (ids.length !== 2) return null;
  const findingA = items.find((item) => item.id === ids[0]);
  const findingB = items.find((item) => item.id === ids[1]);
  return findingA && findingB ? { findingA, findingB } : null;
}

export function shouldShowIterationBar(stage: string | undefined, current: number | undefined): boolean {
  return stage === 'analysis' && typeof current === 'number' && current >= 0;
}
