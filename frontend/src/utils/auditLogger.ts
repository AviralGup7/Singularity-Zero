import { useEffect, useRef, useCallback } from 'react';

export interface AuditEntry {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  details: Record<string, unknown>;
  page?: string;
}

const STORAGE_KEY = 'cyber-pipeline-audit-log';
const MAX_ENTRIES = 1000;

export function logAuditAction(
  action: string,
  details: Record<string, unknown>,
  user = 'anonymous',
  page = typeof window !== 'undefined' ? window.location.pathname : '/ssr'
): void {
  const entry: AuditEntry = {
    id: `audit-${crypto.randomUUID()}`,
    timestamp: new Date().toISOString(),
    user,
    action,
    details,
    page,
  };

  try {
    const existing = getAuditLog();
    existing.unshift(entry);
    if (existing.length > MAX_ENTRIES) {
      existing.length = MAX_ENTRIES;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));
  } catch (e) {
    console.warn('Failed to write audit log:', e);
  }
}

export function parseAuditLog(raw: string | null): AuditEntry[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed as AuditEntry[] : [];
  } catch {
    return [];
  }
}

export function getAuditLog(): AuditEntry[] {
  try {
    return parseAuditLog(localStorage.getItem(STORAGE_KEY));
  } catch {
    return [];
  }
}

export function clearAuditLog(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* private mode / blocked storage */
  }
}

export function useAuditLogger(user = 'anonymous') {
  const userRef = useRef(user);
  useEffect(() => {
    userRef.current = user;
   
  }, [user]);

  const log = useCallback(
    (action: string, details: Record<string, unknown>) => {
      logAuditAction(action, details, userRef.current);
    },
    []
  );

  return { log };
}
