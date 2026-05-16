export type PIICategory = 'email' | 'phone' | 'ssn' | 'creditCard' | 'ipAddress' | 'name' | 'custom';

export interface PIIMatch {
  category: PIICategory;
  value: string;
  redacted: string;
  start: number;
  end: number;
}

export interface PIIAuditEntry {
  id: string;
  timestamp: string;
  action: 'detected' | 'redacted' | 'revealed';
  category: PIICategory;
  context: string;
  user: string;
}

const PII_AUDIT_STORAGE_KEY = 'cyber-pipeline-pii-audit';
const PII_VISIBILITY_KEY = 'cyber-pipeline-pii-visibility';

const REDACTION_MASKS: Record<PIICategory, string> = {
  email: '[EMAIL_REDACTED]',
  phone: '[PHONE_REDACTED]',
  ssn: '[SSN_REDACTED]',
  creditCard: '[CARD_REDACTED]',
  ipAddress: '[IP_REDACTED]',
  name: '[NAME_REDACTED]',
  custom: '[SECRET_REDACTED]',
};

export function detectPII(text: string): PIIMatch[] {
  const matches: PIIMatch[] = [];

  const checks: Array<[PIICategory, RegExp]> = [
    ['email', /[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}/g],
    ['phone', /(?:\+?1[ .-])?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}/g],
    ['ssn', /\b\d{3}-\d{2}-\d{4}\b/g],
    ['creditCard', /\b\d{4}(?:[ -]?\d{4}){3}\b/g],
    ['ipAddress', /\b\d{1,3}(?:\.\d{1,3}){3}\b/g],
    ['name', /(?:Name|User|Author|Owner|Sender|From|Customer|Client|Contact):\s+[A-Z][a-z][\w ]{1,30}/g],
    ['custom', /(?:password|secret|token|api[-_]?key)\s*[:=]\s*[^\s]{3,}/gi],
  ];

  for (const [category, pattern] of checks) {
    const mask = REDACTION_MASKS[category as keyof typeof REDACTION_MASKS];
    let match;
    while ((match = pattern.exec(text)) !== null) {
      matches.push({
        category,
        value: match[0],
        redacted: mask,
        start: match.index,
        end: match.index + match[0].length,
      });
    }
  }

  return matches.sort((a, b) => a.start - b.start);
}

export function redactPII(text: string, categories?: PIICategory[]): string {
  const matches = detectPII(text);
  const filtered = categories
    ? matches.filter((m) => categories.includes(m.category))
    : matches;

  if (filtered.length === 0) return text;

  let result = '';
  let lastIndex = 0;

  for (const match of filtered) {
    result += text.slice(lastIndex, match.start);
    result += match.redacted;
    lastIndex = match.end;
  }

  result += text.slice(lastIndex);
  return result;
}

export function logPIIAction(
  action: PIIAuditEntry['action'],
  category: PIICategory,
  context: string,
  user = 'anonymous'
): void {
  const entry: PIIAuditEntry = {
    id: `pii-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    action,
    category,
    context,
    user,
  };

  try {
    const raw = sessionStorage.getItem(PII_AUDIT_STORAGE_KEY);
    const all: PIIAuditEntry[] = raw ? JSON.parse(raw) : [];
    all.unshift(entry);
    if (all.length > 1000) all.length = 1000;
    sessionStorage.setItem(PII_AUDIT_STORAGE_KEY, JSON.stringify(all));
  } catch (e) {
    console.warn('Failed to write PII audit log:', e);
  }
}

export function getPIIAuditLog(): PIIAuditEntry[] {
  try {
    const raw = sessionStorage.getItem(PII_AUDIT_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function isPIIVisible(): boolean {
  try {
    return sessionStorage.getItem(PII_VISIBILITY_KEY) === 'true';
  } catch {
    return false;
  }
}

export function setPIIVisible(visible: boolean, user = 'anonymous'): void {
  sessionStorage.setItem(PII_VISIBILITY_KEY, String(visible));
  logPIIAction(visible ? 'revealed' : 'redacted', 'custom', 'PII visibility toggled', user);
}

export function scanObjectForPII(obj: unknown): Record<string, PIIMatch[]> {
  const results = new Map<string, PIIMatch[]>();
  const visited = new WeakSet<object>();

  function scan(value: unknown, path: string): void {
    if (typeof value === 'string') {
      const piiMatches = detectPII(value);
      if (piiMatches.length > 0) {
        results.set(path, piiMatches);
      }
    } else if (Array.isArray(value)) {
      value.forEach((item, i) => scan(item, `${path}[${i}]`));
    } else if (value && typeof value === 'object') {
      if (visited.has(value)) return;
      visited.add(value);
      for (const [key, val] of Object.entries(value)) {
        scan(val, path ? `${path}.${key}` : key);
      }
    }
  }

  scan(obj, '');
  return Object.fromEntries(results) as Record<string, PIIMatch[]>;
}

export function redactObjectPII(obj: Record<string, unknown>): Record<string, unknown> {
  function redact(value: unknown): unknown {
    if (typeof value === 'string') {
      return redactPII(value);
    }
    if (Array.isArray(value)) {
      return value.map(redact);
    }
    if (value && typeof value === 'object') {
      const result = new Map<string, unknown>();
      for (const [key, val] of Object.entries(value)) {
        result.set(key, redact(val));
      }
      return Object.fromEntries(result);
    }
    return value;
  }

  return redact(obj) as Record<string, unknown>;
}
