/* eslint-disable security/detect-unsafe-regex, security/detect-non-literal-regexp --
 * These regexes parse short, bounded policy text (length-checked in looksLikeAssetPattern)
 * and are evaluated against substrings of lines, not user-provided regex patterns. */
/**
 * HackerOne / Bugcrowd / Intigriti / raw scope text parser.
 *
 * Operators paste the entire program policy text. We extract:
 *   - in-scope asset patterns (URLs, domains, wildcards, IP ranges)
 *   - out-of-scope asset patterns
 *   - per-asset program-specific notes (bounty ranges, severity, etc.)
 *
 * The parser is intentionally permissive: it tries the structured
 * `Asset identifier` / `Asset type` / `Instruction` lines that H1
 * programs use, falls back to URL/wildcard detection, and gracefully
 * degrades to "everything in the pasted text" if neither heuristic
 * matches.
 */

export type ScopeStatus = 'in_scope' | 'out_of_scope' | 'unknown';

export interface ScopeEntry {
  /** Normalized asset pattern (lowercase, no trailing slash). */
  pattern: string;
  /** Original raw line as pasted by the operator. */
  raw: string;
  status: ScopeStatus;
  /** Free-text notes from the program (e.g. "Critical: $5k, High: $1k"). */
  notes: string;
  /** Optional bounty range in USD when the program lists one. */
  bounty_min_usd?: number;
  bounty_max_usd?: number;
}

export interface ParsedScope {
  in_scope: ScopeEntry[];
  out_of_scope: ScopeEntry[];
  unknown: ScopeEntry[];
  source: 'hackerone' | 'bugcrowd' | 'intigriti' | 'raw';
  total_lines: number;
  unparseable_lines: number;
}

const H1_SECTION_HEADERS = [
  'scope',
  'in-scope assets',
  'in scope',
  'in_scope',
  'out of scope',
  'out-of-scope',
  'out_of_scope',
  'not in scope',
  'not in-scope',
];

function normalizeLine(raw: string): string {
  return raw
    .replace(/\u00a0/g, ' ')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/\s+/g, ' ')
    .trim();
}

function looksLikeAssetPattern(s: string): boolean {
  if (!s) return false;
  if (s.length > 512) return false;
  if (s.startsWith('//') || s.startsWith('#') || s.startsWith(';')) return false;
  // URL or hostname
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return true;
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(s)) return true;
  // Wildcard domain
  if (/^\*\.[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s)) return true;
  // IPv4 / IPv4 CIDR
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)) return true;
  // Android / iOS package ids
  if (/^([a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)$/.test(s) && s.includes('.')) return true;
  // Source code repo URLs
  if (/^https?:\/\/(www\.)?(github|gitlab|bitbucket)\./i.test(s)) return true;
  return false;
}

function extractBountyRange(notes: string): { min?: number; max?: number } {
  if (!notes) return {};
  const rangeMatch = notes.match(/\$?\s*(\d{1,3}(?:,\d{3})*|\d+)\s*[-–]\s*\$?\s*(\d{1,3}(?:,\d{3})*|\d+)/);
  if (rangeMatch) {
    const min = Number(rangeMatch[1].replace(/,/g, ''));
    const max = Number(rangeMatch[2].replace(/,/g, ''));
    if (!Number.isNaN(min) && !Number.isNaN(max)) {
      return { min, max };
    }
  }
  const singleMatch = notes.match(/\$?\s*(\d{1,3}(?:,\d{3})*|\d+)\s*(?:usd|dollar)/i);
  if (singleMatch) {
    const v = Number(singleMatch[1].replace(/,/g, ''));
    if (!Number.isNaN(v)) return { min: v, max: v };
  }
  return {};
}

function detectSource(text: string): ParsedScope['source'] {
  const head = text.slice(0, 2000).toLowerCase();
  if (head.includes('hackerone')) return 'hackerone';
  if (head.includes('bugcrowd')) return 'bugcrowd';
  if (head.includes('intigriti')) return 'intigriti';
  return 'raw';
}

function detectStatus(line: string, currentSection: ScopeStatus): ScopeStatus {
  const lower = line.toLowerCase();
  if (H1_SECTION_HEADERS.some((h) => lower === h || lower.startsWith(h + ':'))) {
    if (lower.includes('out') || lower.includes('not in')) return 'out_of_scope';
    if (lower.includes('in')) return 'in_scope';
  }
  if (lower.startsWith('out of scope') || lower.includes('| out of scope')) return 'out_of_scope';
  if (lower.startsWith('not in scope') || lower.includes('| not in scope')) return 'out_of_scope';
  if (lower.startsWith('in scope') || lower.includes('| in scope')) return 'in_scope';
  return currentSection;
}

function extractPatternAndNotes(line: string): { pattern: string; notes: string } {
  // Common formats:
  //   *.example.com
  //   *.example.com (Production)
  //   https://example.com/admin
  //   Asset identifier: *.example.com  Type: domain  Instructions: ...
  //   *.example.com - critical systems
  const m = line.match(/Asset identifier\s*[:=]\s*(\S+)(?:\s+Type\s*[:=]\s*(\S+))?(?:\s+Instructions?\s*[:=]\s*(.+))?$/i);
  if (m) {
    return { pattern: m[1], notes: [m[2] || '', m[3] || ''].filter(Boolean).join(' - ').trim() };
  }
  const idx = line.search(/\s[([{]/);
  if (idx > 0) {
    return { pattern: line.slice(0, idx).trim(), notes: line.slice(idx + 1).replace(/[\])}]$/, '').trim() };
  }
  const dashIdx = line.search(/\s+[-–]\s+/);
  if (dashIdx > 0) {
    return { pattern: line.slice(0, dashIdx).trim(), notes: line.slice(dashIdx + 3).trim() };
  }
  return { pattern: line.trim(), notes: '' };
}

export function parseScopeText(text: string): ParsedScope {
  const result: ParsedScope = {
    in_scope: [],
    out_of_scope: [],
    unknown: [],
    source: detectSource(text),
    total_lines: 0,
    unparseable_lines: 0,
  };

  if (!text || !text.trim()) return result;

  const lines = text.split(/\r?\n/);
  let section: ScopeStatus = 'unknown';
  result.total_lines = lines.length;

  for (const raw of lines) {
    const line = normalizeLine(raw);
    if (!line) continue;
    const newSection = detectStatus(line, section);
    if (newSection !== section && (
      line.toLowerCase() === newSection.replace('_', ' ') ||
      H1_SECTION_HEADERS.some((h) => line.toLowerCase().startsWith(h))
    )) {
      section = newSection;
      continue;
    }
    if (!looksLikeAssetPattern(line)) {
      result.unparseable_lines++;
      continue;
    }
    const { pattern, notes } = extractPatternAndNotes(line);
    const normalized = pattern.toLowerCase().replace(/\/+$/, '');
    const entry: ScopeEntry = {
      pattern: normalized,
      raw: line,
      status: section,
      notes,
      ...extractBountyRange(notes),
    };
    if (entry.status === 'in_scope') result.in_scope.push(entry);
    else if (entry.status === 'out_of_scope') result.out_of_scope.push(entry);
    else {
      entry.status = 'in_scope';
      result.in_scope.push(entry);
    }
  }

  // De-dupe by pattern, preserving the most informative entry.
  const dedup = (entries: ScopeEntry[]) => {
    const map = new Map<string, ScopeEntry>();
    for (const e of entries) {
      const existing = map.get(e.pattern);
      if (!existing) {
        map.set(e.pattern, e);
      } else if (e.notes.length > existing.notes.length) {
        map.set(e.pattern, e);
      }
    }
    return Array.from(map.values());
  };
  result.in_scope = dedup(result.in_scope);
  result.out_of_scope = dedup(result.out_of_scope);

  return result;
}

/**
 * Returns 'in_scope' | 'out_of_scope' | 'unknown' for a given asset string
 * (hostname, URL, wildcard) against a parsed scope. Used by the target-cards
 * scope-compliance badge so operators can see at a glance whether a target
 * is in-scope for the imported program.
 */
export function classifyAgainstScope(
  asset: string,
  scope: ParsedScope | null,
): { status: ScopeStatus; matchingEntry?: ScopeEntry } {
  if (!scope) return { status: 'unknown' };
  const a = asset.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');

  for (const e of scope.out_of_scope) {
    if (matchesScope(a, e.pattern)) return { status: 'out_of_scope', matchingEntry: e };
  }
  for (const e of scope.in_scope) {
    if (matchesScope(a, e.pattern)) return { status: 'in_scope', matchingEntry: e };
  }
  return { status: 'unknown' };
}

function matchesScope(asset: string, pattern: string): boolean {
  if (!asset || !pattern) return false;
  if (asset === pattern) return true;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1);
    return asset.endsWith(suffix) || asset === pattern.slice(2);
  }
  if (pattern.startsWith('*.') === false && pattern.includes('*')) {
    const re = new RegExp('^' + pattern.split('*').map(escapeRe).join('.*') + '$');
    return re.test(asset);
  }
  // Subdomain match: scope `example.com` matches `api.example.com`.
  if (asset.endsWith('.' + pattern)) return true;
  return false;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
