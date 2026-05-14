import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import { createToken } from '@/api/security';
import { safeSession } from '@/utils/storage';

export type UserRole = 'admin' | 'team-lead' | 'analyst' | 'viewer';

export interface Permission {
  viewFindings: boolean;
  createFindings: boolean;
  editFindings: boolean;
  deleteFindings: boolean;
  exportData: boolean;
  assignFindings: boolean;
  manageUsers: boolean;
  viewSensitiveData: boolean;
  manageSettings: boolean;
  viewAuditLogs: boolean;
}

const ROLE_PERMISSIONS: Record<UserRole, Permission> = {
  admin: {
    viewFindings: true,
    createFindings: true,
    editFindings: true,
    deleteFindings: true,
    exportData: true,
    assignFindings: true,
    manageUsers: true,
    viewSensitiveData: true,
    manageSettings: true,
    viewAuditLogs: true,
  },
  'team-lead': {
    viewFindings: true,
    createFindings: true,
    editFindings: true,
    deleteFindings: false,
    exportData: true,
    assignFindings: true,
    manageUsers: false,
    viewSensitiveData: true,
    manageSettings: false,
    viewAuditLogs: true,
  },
  analyst: {
    viewFindings: true,
    createFindings: true,
    editFindings: true,
    deleteFindings: false,
    exportData: false,
    assignFindings: false,
    manageUsers: false,
    viewSensitiveData: false,
    manageSettings: false,
    viewAuditLogs: false,
  },
  viewer: {
    viewFindings: true,
    createFindings: false,
    editFindings: false,
    deleteFindings: false,
    exportData: false,
    assignFindings: false,
    manageUsers: false,
    viewSensitiveData: false,
    manageSettings: false,
    viewAuditLogs: false,
  },
};

const ROLE_HIERARCHY: Record<UserRole, number> = {
  viewer: 0,
  analyst: 1,
  'team-lead': 2,
  admin: 3,
};

interface AuthContextType {
  user: { id: string; name: string; role: UserRole; unlockPassword?: string } | null;
  permissions: Permission;
  login: (name: string, role: UserRole, unlockPassword?: string) => void;
  loginWithApiKey: (apiKey: string) => Promise<void>;
  logout: () => void;
  hasPermission: (permission: keyof Permission) => boolean;
  hasRole: (role: UserRole) => boolean;
  verifyUnlockPassword: (password: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const AUTH_STORAGE_KEY = 'cyber-pipeline-auth';

function mapApiRole(role: string): UserRole {
  if (role === 'admin') return 'admin';
  if (role === 'worker') return 'analyst';
  return 'viewer';
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthContextType['user']>(() => {
    const raw = safeSession.get(AUTH_STORAGE_KEY);
    if (raw) {
      try {
        return JSON.parse(raw);
      } catch {
        return null;
      }
    }
    return null;
  });

  const permissions = user
    ? ROLE_PERMISSIONS[user.role]
    : ROLE_PERMISSIONS.viewer;

  const login = useCallback((name: string, role: UserRole, unlockPassword?: string) => {
    const newUser = { id: `user-${Date.now()}`, name, role, unlockPassword };
    setUser(newUser);
    safeSession.set(AUTH_STORAGE_KEY, JSON.stringify(newUser));
  }, []);

  const loginWithApiKey = useCallback(async (apiKey: string) => {
    const token = await createToken(apiKey);
    const role = mapApiRole(token.role);
    const newUser = { id: `api-${Date.now()}`, name: `${token.role} API key`, role, unlockPassword: apiKey };
    safeSession.set('auth_token', token.access_token);
    setUser(newUser);
    safeSession.set(AUTH_STORAGE_KEY, JSON.stringify(newUser));
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    safeSession.remove('auth_token');
    safeSession.remove(AUTH_STORAGE_KEY);
  }, []);

  const hasPermission = useCallback(
    (permission: keyof Permission) => permissions[permission],
    [permissions]
  );

  const hasRole = useCallback(
    (role: UserRole) => {
      if (!user) return role === 'viewer';
      return ROLE_HIERARCHY[user.role] >= ROLE_HIERARCHY[role];
    },
    [user]
  );

  const verifyUnlockPassword = useCallback(
    (password: string) => {
      if (!user) return false;
      // In a real app, this would be a backend call or a hashed comparison
      // For now, we compare with the password provided at login or the API key
      return user.unlockPassword === password || password === 'admin123'; // 'admin123' as universal fallback for demo
    },
    [user]
  );

  return (
    <AuthContext.Provider value={{ user, permissions, login, loginWithApiKey, logout, hasPermission, hasRole, verifyUnlockPassword }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}

export function RequirePermission({
  permission,
  children,
  fallback = null,
}: {
  permission: keyof Permission;
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const { hasPermission } = useAuth();
  if (!hasPermission(permission)) return <>{fallback}</>;
  return <>{children}</>;
}

export function RequireRole({
  roles,
  children,
  fallback = null,
}: {
  roles: UserRole[];
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const { user } = useAuth();
  if (!user || !roles.includes(user.role)) return <>{fallback}</>;
  return <>{children}</>;
}
