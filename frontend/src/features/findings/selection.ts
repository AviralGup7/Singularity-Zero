export function pruneSelection(selected: Iterable<string>, visible: Iterable<string>): string[] {
  const allowed = new Set(visible);
  return Array.from(selected).filter((id) => allowed.has(id));
}

export function shouldShowIterationBar(stage: string | undefined, current: number | undefined): boolean {
  return stage === 'analysis' && typeof current === 'number' && current >= 0;
}
