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
  page = window.location.pathname
): void {
  const entry: AuditEntry = {
    id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
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

export function getAuditLog(): AuditEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function clearAuditLog(): void {
  sessionStorage.removeItem(STORAGE_KEY);
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
