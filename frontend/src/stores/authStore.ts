import { create } from 'zustand';
import { createToken, createGuestToken, verifyAuthToken } from '@/api/security';
import type { TokenResponse } from '@/api/security';
import { safeSession, safeStorage } from '@/utils/storage';
import type { AuthContextType } from '@/context/auth-context';
import type { UserRole } from '@/types/auth';
import type { Permission } from '@/types/auth';

/** Sanitize user object before serialization — never persist secrets. */
function sanitizeUser(user: {
  id: string; name: string; role: UserRole; unlockPassword?: string;
  tenantId: string; organizationId: string;
}) {
  const { unlockPassword: _secret, ...safe } = user;
  return safe;
}

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
  const normalized = role?.toLowerCase() ?? '';
  if (normalized === 'admin' || normalized === 'superadmin') return 'admin';
  if (normalized === 'team-lead' || normalized === 'team_lead' || normalized === 'lead') return 'team-lead';
  if (normalized === 'worker' || normalized === 'analyst') return 'analyst';
  if (normalized === 'viewer' || normalized === 'guest') return 'viewer';
  return 'viewer';
}

function getInitialUser() {
  const raw = safeSession.get(AUTH_STORAGE_KEY) || safeStorage.get(AUTH_STORAGE_KEY);
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      return {
        tenantId: 'tenant-default',
        organizationId: 'org-default',
        ...parsed,
      } as { id: string; name: string; role: UserRole; tenantId: string; organizationId: string };
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
      tenantId: 'tenant-default',
      organizationId: 'org-default',
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
      const newUser = {
        id: `user-${Date.now()}`,
        name,
        role,
        unlockPassword,
        tenantId: 'tenant-default',
        organizationId: 'org-default',
      };
      safeSession.set(AUTH_STORAGE_KEY, JSON.stringify(sanitizeUser(newUser)));
      set({
        user: newUser,
        // ``role`` is a ``UserRole`` string-literal union and ``ROLE_PERMISSIONS``
        // exhaustively covers every member of that union, so the dynamic key
        // can never be a value outside the record.
        /* eslint-disable-next-line security/detect-object-injection */
        permissions: ROLE_PERMISSIONS[role],
      });
    },

    loginWithGuestToken: async () => {
      // Lazy import to break circular dependency with settingsStore
      const { useSettingsStore } = await import('./settingsStore');
      const baseUrl = useSettingsStore.getState().settings.api.baseUrl
        || (typeof window !== 'undefined' ? window.location.origin : '');
      const result = await createGuestToken(baseUrl || undefined);
      if (!result.ok || !result.data) {
        throw new Error(result.error?.message || 'Guest authentication failed');
      }
      const token = result.data;
      const newUser = {
        id: `guest-${Date.now()}`,
        name: 'Guest',
        role: 'viewer' as UserRole,
        tenantId: 'tenant-default',
        organizationId: 'org-default',
      };
      safeSession.set('auth_token', token.access_token);
      safeSession.set(AUTH_STORAGE_KEY, JSON.stringify(newUser));
      set({
        user: newUser,
        permissions: ROLE_PERMISSIONS.viewer,
      });
    },

    loginWithApiKey: async (apiKey: string) => {
      const token = await createToken(apiKey);
      const role = mapApiRole(token.role);
      const tokenExt = token as TokenResponse & { tenant_id?: string; organization_id?: string };
      const newUser = {
        id: `api-${Date.now()}`,
        name: `${token.role} API key`,
        role,
        tenantId: tokenExt.tenant_id || 'tenant-default',
        organizationId: tokenExt.organization_id || 'org-default',
      };
      safeSession.set('auth_token', token.access_token);
      safeSession.set(AUTH_STORAGE_KEY, JSON.stringify(sanitizeUser(newUser)));
      set({
        user: newUser,
        /* eslint-disable-next-line security/detect-object-injection */
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
      // ``permission`` is typed as ``keyof Permission`` so the lookup
      // is statically bounded to the union members of the record.
      /* eslint-disable-next-line security/detect-object-injection */
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

    hydrateAuth: async () => {
      const state = get();
      // Only verify if we have a persisted user but no live token
      if (!state.user) return;
      const token = safeSession.get('auth_token');
      if (!token) {
        // Token was cleared (e.g.另一 tab) — clear the user too
        set({ user: null, permissions: ROLE_PERMISSIONS.viewer });
        return;
      }
      try {
        const result = await verifyAuthToken();
        if (!result.valid) {
          // Token expired or revoked — clear session
          safeSession.remove('auth_token');
          safeSession.remove(AUTH_STORAGE_KEY);
          set({ user: null, permissions: ROLE_PERMISSIONS.viewer });
        }
      } catch {
        // Network error — keep existing session, will retry on next request
      }
    },
  };
});
