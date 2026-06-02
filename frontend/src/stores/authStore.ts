import { create } from 'zustand';
import { createToken } from '@/api/security';
import { safeSession, safeStorage } from '@/utils/storage';
import type { AuthContextType } from '@/context/auth-context';
import type { UserRole } from '@/types/auth';
import type { Permission } from '@/types/auth';

const ROLE_PERMISSIONS: Record<UserRole, Permission> = {
  admin: {
    viewFindings: true, createFindings: true, editFindings: true, deleteFindings: true,
    exportData: true, assignFindings: true, manageUsers: true, viewSensitiveData: true,
    manageSettings: true, viewAuditLogs: true,
  },
  'team-lead': {
    viewFindings: true, createFindings: true, editFindings: true, deleteFindings: false,
    exportData: true, assignFindings: true, manageUsers: false, viewSensitiveData: true,
    manageSettings: false, viewAuditLogs: true,
  },
  analyst: {
    viewFindings: true, createFindings: true, editFindings: true, deleteFindings: false,
    exportData: false, assignFindings: false, manageUsers: false, viewSensitiveData: false,
    manageSettings: false, viewAuditLogs: false,
  },
  viewer: {
    viewFindings: true, createFindings: false, editFindings: false, deleteFindings: false,
    exportData: false, assignFindings: false, manageUsers: false, viewSensitiveData: false,
    manageSettings: false, viewAuditLogs: false,
  },
};

const ROLE_HIERARCHY = new Map<UserRole, number>([
  ['viewer', 0],
  ['analyst', 1],
  ['team-lead', 2],
  ['admin', 3]
]);

const AUTH_STORAGE_KEY = 'cyber-pipeline-auth';

function mapApiRole(role: string): UserRole {
  if (role === 'admin') return 'admin';
  if (role === 'worker') return 'analyst';
  return 'viewer';
}

function getInitialUser() {
  const raw = safeSession.get(AUTH_STORAGE_KEY) || safeStorage.get(AUTH_STORAGE_KEY);
  if (raw) {
    try {
      return JSON.parse(raw) as { id: string; name: string; role: UserRole; unlockPassword?: string };
    } catch {
      return null;
    }
  }
  // Playwright E2E Test bypass: automatically authorize as admin when running in Playwright harness
  if (import.meta.env.DEV && typeof window !== 'undefined' && window.navigator.userAgent.includes('Playwright')) {
    return {
      id: 'e2e-user',
      name: 'E2E Analyst',
      role: 'admin' as UserRole,
    };
  }
  return null;
}

export type AuthStore = AuthContextType;

export const useAuthStore = create<AuthStore>((set, get) => {
  const initialUser = getInitialUser();
  const initialPermissions = initialUser ? ROLE_PERMISSIONS[initialUser.role] : ROLE_PERMISSIONS.viewer;

  return {
    user: initialUser,
    permissions: initialPermissions,

    login: (name: string, role: UserRole, unlockPassword?: string) => {
      const newUser = { id: `user-${Date.now()}`, name, role, unlockPassword };
      safeSession.set(AUTH_STORAGE_KEY, JSON.stringify(newUser));
      set({
        user: newUser,
        permissions: ROLE_PERMISSIONS[role],
      });
    },

    loginWithApiKey: async (apiKey: string) => {
      const token = await createToken(apiKey);
      const role = mapApiRole(token.role);
      const newUser = { id: `api-${Date.now()}`, name: `${token.role} API key`, role, unlockPassword: apiKey };
      safeSession.set('auth_token', token.access_token);
      safeSession.set(AUTH_STORAGE_KEY, JSON.stringify(newUser));
      set({
        user: newUser,
        permissions: ROLE_PERMISSIONS[role],
      });
    },

    logout: () => {
      safeSession.remove('auth_token');
      safeSession.remove(AUTH_STORAGE_KEY);
      set({
        user: null,
        permissions: ROLE_PERMISSIONS.viewer,
      });
    },

    hasPermission: (permission: keyof Permission) => {
      const state = get();
      return state.permissions[permission] === true;
    },

    hasRole: (role: UserRole) => {
      const state = get();
      if (!state.user) return role === 'viewer';
      return (ROLE_HIERARCHY.get(state.user.role) ?? 0) >= (ROLE_HIERARCHY.get(role) ?? 0);
    },

    verifyUnlockPassword: (password: string) => {
      const state = get();
      if (!state.user) return false;
      return state.user.unlockPassword === password;
    },
  };
});
