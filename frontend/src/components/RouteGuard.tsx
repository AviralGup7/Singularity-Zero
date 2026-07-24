import { Navigate, useLocation, Link, useParams } from 'react-router-dom';
import { ROUTES } from '@/config/paths';
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
  const params = useParams();

  if (!user) {
    return <Navigate to={ROUTES.LOGIN} state={{ from: location }} replace />;
  }

  // Tenant/Workspace context gating
  const queryParams = new URLSearchParams(location.search);
  const requestedTenant = params.tenantId || queryParams.get('tenantId') || queryParams.get('tenant') || queryParams.get('orgId');

  if (requestedTenant && user.tenantId && requestedTenant !== user.tenantId) {
    return (
      <div className="p-8 text-center text-muted max-w-md mx-auto" role="alert">
        <div className="mb-4 text-4xl" aria-hidden="true">🚫</div>
        <h2 className="text-xl font-semibold mb-2 text-text">Access Denied</h2>
        <p className="mb-4">You do not have permission to access resources outside your tenant boundary.</p>
        <Link
          to="/"
          className="btn btn-primary inline-flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider"
        >
          Return to Dashboard
        </Link>
      </div>
    );
  }

  // Role-based check: user must have at least the required role level
  if (requiredRole && !hasRole(requiredRole)) {
    return <Navigate to="/" replace />;
  }

  // Permission-based check: user must have the specific permission
  if (requiredPermission && !hasPermission(requiredPermission)) {
    return (
      <div className="p-8 text-center text-muted max-w-md mx-auto" role="alert">
        <div className="mb-4 text-4xl" aria-hidden="true">🔒</div>
        <h2 className="text-xl font-semibold mb-2 text-text">Access Denied</h2>
        <p className="mb-4">You do not have permission to access this page.</p>
        <Link
          to="/"
          className="btn btn-primary inline-flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider"
        >
          Return to Dashboard
        </Link>
      </div>
    );
  }

  return <>{children}</>;
}
