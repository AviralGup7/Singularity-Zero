import { useAuthStore } from '../stores/authStore';
import type { AuthContextType } from '../context/auth-context';

export function useAuth(): AuthContextType {
  return useAuthStore();
}
