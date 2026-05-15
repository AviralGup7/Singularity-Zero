import { Navigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import type { UserRole } from '@/context/AuthContext';
import type { ReactNode } from 'react';

interface RouteGuardProps {
  children: ReactNode;
  requiredRole?: UserRole;
  /** Require a specific permission (e.g., 'manageSettings', 'exportData') */
  requiredPermission?: keyof ReturnType<typeof useAuth>['permissions'];
}

export function RouteGuard({ children, requiredRole, requiredPermission }: RouteGuardProps) {
  const { user, hasRole, hasPermission } = useAuth();
  const location = useLocation();

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Role-based check: user must have at least the required role level
  if (requiredRole && !hasRole(requiredRole)) {
    return <Navigate to="/" replace />;
  }

  // Permission-based check: user must have the specific permission
  if (requiredPermission && !hasPermission(requiredPermission)) {
    return (
      <div className="p-8 text-center text-muted" role="alert">
        <h2 className="text-xl font-semibold mb-2">Access Denied</h2>
        <p>You do not have permission to access this page.</p>
        <Link to="/" className="text-blue-400 hover:underline mt-4 inline-block">
          Return to Dashboard
        </Link>
      </div>
    );
  }

  return <>{children}</>;
}
