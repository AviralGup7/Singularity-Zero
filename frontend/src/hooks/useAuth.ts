import { useAuthStore } from '../stores/authStore';
import type { AuthContextType } from '../context/AuthContext';

export function useAuth(): AuthContextType {
  return useAuthStore();
}
