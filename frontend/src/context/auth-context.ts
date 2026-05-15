import { createContext } from 'react';

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

export interface AuthContextType {
  user: { id: string; name: string; role: UserRole; unlockPassword?: string } | null;
  permissions: Permission;
  login: (name: string, role: UserRole, unlockPassword?: string) => void;
  loginWithApiKey: (apiKey: string) => Promise<void>;
  logout: () => void;
  hasPermission: (permission: keyof Permission) => boolean;
  hasRole: (role: UserRole) => boolean;
  verifyUnlockPassword: (password: string) => boolean;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);
