import { createContext, useContext  } from 'react';
import type {ReactNode} from 'react';
import { useTargets } from '../hooks';
import type { Target } from '@/types/api';

interface TargetsContextValue {
  targets: Target[];
  loading: boolean;
  error: ReturnType<typeof useTargets>['error'];
  refetch: () => Promise<void>;
  totalTargets: number;
  targetsByStatus: Record<string, number>;
}

const TargetsContext = createContext<TargetsContextValue | null>(null);

export function TargetsProvider({ children, enabled = true }: { children: ReactNode; enabled?: boolean }) {
  const { data, loading, error, refetch } = useTargets({ enabled });

  const targets = data?.targets ?? [];
  const totalTargets = targets.length;
  
  const targetsByStatus = targets.reduce((acc, _t) => {
    const status = 'active';
    acc[status] = (acc[status] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <TargetsContext.Provider value={{ targets, loading, error, refetch, totalTargets, targetsByStatus }}>
      {children}
    </TargetsContext.Provider>
  );
}

export function useTargetsContext() {
  const context = useContext(TargetsContext);
  if (!context) {
    throw new Error('useTargetsContext must be used within a TargetsProvider');
  }
  return context;
}