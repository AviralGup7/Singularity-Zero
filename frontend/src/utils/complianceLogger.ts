export interface ComplianceLogEntry {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  resource: string;
  reason: string;
  details: Record<string, unknown>;
  outcome: 'success' | 'failure' | 'denied';
}

const COMPLIANCE_STORAGE_KEY = 'cyber-pipeline-compliance-log';
export const MAX_COMPLIANCE_ENTRIES = 1000;

export function capComplianceLogs<T>(entries: T[], max = MAX_COMPLIANCE_ENTRIES): T[] {
  return entries.length > max ? entries.slice(0, max) : entries;
}

export function logComplianceAction(
  action: string,
  resource: string,
  reason: string,
  details: Record<string, unknown> = {},
  user = 'anonymous',
   
  outcome: ComplianceLogEntry['outcome'] = 'success'
): ComplianceLogEntry {
  const entry: ComplianceLogEntry = {
    id: `compliance-${crypto.randomUUID()}`,
    timestamp: new Date().toISOString(),
    user,
    action,
    resource,
    reason,
    details,
    outcome,
  };

  try {
    const existing = getComplianceLogs();
    existing.unshift(entry);
    if (existing.length > MAX_COMPLIANCE_ENTRIES) existing.length = MAX_COMPLIANCE_ENTRIES;
    sessionStorage.setItem(COMPLIANCE_STORAGE_KEY, JSON.stringify(existing));
  } catch (e) {
    console.warn('Failed to write compliance log:', e);
  }

  return entry;
}

export function parseComplianceLogs(raw: string | null): ComplianceLogEntry[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed as ComplianceLogEntry[] : [];
  } catch {
    return [];
  }
}

export function getComplianceLogs(): ComplianceLogEntry[] {
  try {
    return parseComplianceLogs(sessionStorage.getItem(COMPLIANCE_STORAGE_KEY));
  } catch {
    return [];
  }
}

export function escapeCSVValue(val: string): string {
  let next = val;
  if (/^[=+\-@\t\r]/.test(next)) next = `'${next}`;
  return next.replace(/"/g, '""');
}

export function exportComplianceReport(format: 'json' | 'csv' = 'json'): string {
  const logs = getComplianceLogs();

  if (format === 'csv') {
   
    const headers = ['ID', 'Timestamp', 'User', 'Action', 'Resource', 'Reason', 'Outcome'];
    const rows = logs.map((e) => [
      e.id,
      e.timestamp,
      e.user,
      e.action,
      e.resource,
      e.reason,
      e.outcome,
    ]);
   
    return [headers, ...rows].map((r) => r.map((c) => `"${escapeCSVValue(String(c))}"`).join(',')).join('\n');
  }

  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      totalEntries: logs.length,
      entries: logs,
    },
    null,
    2
  );
}


