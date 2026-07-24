import { createContext  } from 'react';
import type {ReactNode} from 'react';
import type { UserRole, Permission } from '@/types/auth';
import { useAuthStore } from '@/stores/authStore';
import { useAuth } from '@/hooks/useAuth';

export interface AuthContextType {
  user: { id: string; name: string; role: UserRole; unlockPassword?: string; tenantId?: string; organizationId?: string } | null;
  permissions: Permission;
  login: (name: string, role: UserRole, unlockPassword?: string) => void;
  loginWithApiKey: (apiKey: string) => Promise<void>;
  loginWithGuestToken: () => Promise<void>;
  logout: () => void;
  hasPermission: (permission: keyof Permission) => boolean;
  hasRole: (role: UserRole) => boolean;
  verifyUnlockPassword: (password: string) => boolean;
  hydrateAuth: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);
export type { UserRole, Permission };

export function AuthProvider({ children }: { children: ReactNode }) {
  const store = useAuthStore();

  return (
    <AuthContext.Provider value={store}>
      {children}
    </AuthContext.Provider>
  );
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
