import { createContext } from 'react';
import type { UserRole, Permission } from '@/types/auth';

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
