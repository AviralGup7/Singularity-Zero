import type { ReactNode } from 'react';
import { useRole, type UserRole, type Permission } from '@/utils/rolePermissions';

export function RoleGate({
  children,
  requiredRole,
  fallback = null,
}: {
  children: ReactNode;
  requiredRole: UserRole | UserRole[];
  fallback?: ReactNode;
}) {
  const { role } = useRole();

  // Role hierarchy for comparison (higher index = more permissions)
   
  const ROLE_HIERARCHY: UserRole[] = ['viewer', 'analyst', 'team_lead', 'admin'];

   
  const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
  const userLevel = ROLE_HIERARCHY.indexOf(role);
  const hasAccess = roles.some(r => userLevel >= ROLE_HIERARCHY.indexOf(r));

  if (!hasAccess) return <>{fallback}</>;
  return <>{children}</>;
}

export function PermissionGate({
  children,
  permission,
  fallback = null,
}: {
  children: ReactNode;
  permission: keyof Permission;
  fallback?: ReactNode;
}) {
  const { permissions } = useRole();

  if (!permissions[permission]) return <>{fallback}</>;
  return <>{children}</>;
}

/**
 * Development-only role selector.
 * Only renders in development mode to prevent accidental
 * role switching in production.
 */
export function RoleSelector() {
  const { role, updateRole } = useRole();
  const isUserRole = (value: string): value is UserRole =>
    value === 'admin' || value === 'team_lead' || value === 'analyst' || value === 'viewer';

  // SECURITY: Only render in development mode
  if (import.meta.env.PROD) {
    return null;
  }

  return (
    <div className="role-selector">
      <label htmlFor="role-select" className="role-selector-label">
        Current Role (Dev)
      </label>
      <select
        id="role-select"
        className="form-select"
        value={role}
        onChange={e => {
          if (isUserRole(e.target.value)) updateRole(e.target.value);
        }}
      >
        <option value="admin">Admin</option>
        <option value="team_lead">Team Lead</option>
        <option value="analyst">Analyst</option>
        <option value="viewer">Viewer</option>
      </select>
    </div>
  );
}
