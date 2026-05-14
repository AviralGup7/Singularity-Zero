/**
 * Role-based access control utilities.
 *
 * WARNING: Role is stored in sessionStorage without cryptographic protection.
 * The storage includes a simple hash-based integrity check to detect casual tampering,
 * but a determined attacker can still bypass this. Server-side validation is REQUIRED
 * for any security-sensitive operations.
 */
import { useState, useCallback, useMemo, useEffect } from 'react';

export type UserRole = 'admin' | 'team_lead' | 'analyst' | 'viewer';

export interface Permission {
  canExport: boolean;
  canAssign: boolean;
  canDelete: boolean;
  canViewSensitive: boolean;
  canManageUsers: boolean;
  canViewPII: boolean;
  canModifySettings: boolean;
}

const ROLE_PERMISSIONS: Record<UserRole, Permission> = {
  admin: {
    canExport: true,
    canAssign: true,
    canDelete: true,
    canViewSensitive: true,
    canManageUsers: true,
    canViewPII: true,
    canModifySettings: true,
  },
  team_lead: {
    canExport: true,
    canAssign: true,
    canDelete: false,
    canViewSensitive: true,
    canManageUsers: false,
    canViewPII: true,
    canModifySettings: false,
  },
  analyst: {
    canExport: false,
    canAssign: false,
    canDelete: false,
    canViewSensitive: false,
    canManageUsers: false,
    canViewPII: false,
    canModifySettings: false,
  },
  viewer: {
    canExport: false,
    canAssign: false,
    canDelete: false,
    canViewSensitive: false,
    canManageUsers: false,
    canViewPII: false,
    canModifySettings: false,
  },
};

const STORAGE_KEY = 'cyber-pipeline-user-role';
const STORAGE_INTEGRITY_KEY = 'cyber-pipeline-user-role-integrity';

function computeIntegrityHash(role: string): string {
  return btoa(role + '-cyber-pipeline-secret-2024');
}

export function getCurrentRole(): UserRole {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    const integrity = sessionStorage.getItem(STORAGE_INTEGRITY_KEY);
    if (raw && (['admin', 'team_lead', 'analyst', 'viewer'] as string[]).includes(raw)) {
      if (integrity !== computeIntegrityHash(raw)) {
        console.warn('Role integrity check failed - potential tampering detected');
        return 'analyst';
      }
      return raw as UserRole;
    }
  } catch {
    /* ignore */
  }
  return 'analyst';
}

export function setCurrentRole(role: UserRole): void {
  sessionStorage.setItem(STORAGE_KEY, role);
  sessionStorage.setItem(STORAGE_INTEGRITY_KEY, computeIntegrityHash(role));
}

/**
 * React hook for role-based access.
 * Note: Each component instance has independent state.
 * For shared state across components, use a context wrapper.
 */
export function useRole(): { role: UserRole; permissions: Permission; updateRole: (newRole: UserRole) => void } {
  const [role, setRole] = useState<UserRole>(getCurrentRole);

  // Sync with changes from other tabs
  useEffect(() => {
    const handler = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY && e.newValue && (['admin', 'team_lead', 'analyst', 'viewer'] as string[]).includes(e.newValue)) {
        setRole(e.newValue as UserRole);
      }
    };
    window.addEventListener('storage', handler);
    return () => window.removeEventListener('storage', handler);
  }, []);

  const permissions = useMemo(() => ROLE_PERMISSIONS[role], [role]);

  const updateRole = useCallback((newRole: UserRole) => {
    setRole(newRole);
    setCurrentRole(newRole);
  }, []);

  return { role, permissions, updateRole };
}
