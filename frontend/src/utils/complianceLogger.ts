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

export function logComplianceAction(
  action: string,
  resource: string,
  reason: string,
  details: Record<string, unknown> = {},
  user = 'anonymous',
   
  outcome: ComplianceLogEntry['outcome'] = 'success'
): ComplianceLogEntry {
  const entry: ComplianceLogEntry = {
    id: `compliance-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
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
    sessionStorage.setItem(COMPLIANCE_STORAGE_KEY, JSON.stringify(existing));
  } catch (e) {
    console.warn('Failed to write compliance log:', e);
  }

  return entry;
}

export function getComplianceLogs(): ComplianceLogEntry[] {
  try {
    const raw = sessionStorage.getItem(COMPLIANCE_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function getComplianceLogsByUser(user: string): ComplianceLogEntry[] {
  return getComplianceLogs().filter((e) => e.user === user);
}

export function getComplianceLogsByAction(action: string): ComplianceLogEntry[] {
  return getComplianceLogs().filter((e) => e.action === action);
}

export function getComplianceLogsByDateRange(start: Date, end: Date): ComplianceLogEntry[] {
  return getComplianceLogs().filter((e) => {
    const ts = new Date(e.timestamp);
    return ts >= start && ts <= end;
  });
}

function escapeCSVValue(val: string): string {
   
  if (/[=+\-@]/.test(val.charAt(0))) {
    return "'" + val;
  }
  return val;
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

export function clearComplianceLogs(): void {
  sessionStorage.removeItem(COMPLIANCE_STORAGE_KEY);
}

export function useComplianceLogger(user = 'anonymous') {
  return {
    log: (
      action: string,
      resource: string,
      reason: string,
      details: Record<string, unknown> = {},
   
      outcome?: ComplianceLogEntry['outcome']
    ) => logComplianceAction(action, resource, reason, details, user, outcome),
    getLogs: getComplianceLogs,
    exportReport: exportComplianceReport,
  };
}
