import { type ReactNode } from 'react';
import { AuthContext } from './auth-context';
import { useAuthStore } from '@/stores/authStore';
import { useAuth } from '@/hooks/useAuth';

import type { UserRole, Permission, AuthContextType } from './auth-context';
export type { UserRole, Permission, AuthContextType };

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

