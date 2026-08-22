export function userInitials(name?: string | null): string {
  const parts = String(name ?? '').trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return 'A';
  return parts.map((part) => part[0] ?? '').join('').toUpperCase().slice(0, 2) || 'A';
}

export function shortcutGlyph(platform = typeof navigator !== 'undefined' ? navigator.platform : ''): string {
  return /Mac|iPhone|iPad|iPod/i.test(platform) ? '⌘ K' : 'Ctrl+K';
}

export function isSparseEvidence(evidence: unknown): boolean {
  if (evidence === undefined || evidence === null || evidence === '') return true;
  if (typeof evidence === 'string') return evidence.trim().length === 0;
  try {
    const text = JSON.stringify(evidence);
    return text === '{}' || text === '[]' || text === 'null' || text === '""';
  } catch {
    return true;
  }
}
