import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type { ParsedScope } from '@/utils/scopeParser';
import { parseScopeText } from '@/utils/scopeParser';
import { useAuthStore } from './authStore';

const customTenantStorage = {
  getItem: (name: string): string | null => {
    const tenantId = useAuthStore.getState().user?.tenantId || 'tenant-default';
    return localStorage.getItem(`${name}:${tenantId}`) || localStorage.getItem(name);
  },
  setItem: (name: string, value: string): void => {
    const tenantId = useAuthStore.getState().user?.tenantId || 'tenant-default';
    localStorage.setItem(`${name}:${tenantId}`, value);
  },
  removeItem: (name: string): void => {
    const tenantId = useAuthStore.getState().user?.tenantId || 'tenant-default';
    localStorage.removeItem(`${name}:${tenantId}`);
  }
};

interface ScopeState {
  /** Program identifier (e.g. `hackerone-shopify`). */
  programHandle: string;
  /** The most recently parsed scope. */
  parsed: ParsedScope | null;
  /** Raw text the operator pasted (kept so they can re-parse after editing). */
  raw: string;
  /** ISO timestamp of the last successful import. */
  importedAt: string | null;
  setProgramHandle: (handle: string) => void;
  setRaw: (raw: string) => void;
  importRaw: (raw: string) => ParsedScope | null;
  clear: () => void;
}

export const useScopeStore = create<ScopeState>()(
  persist(
    (set, _get) => ({
      programHandle: '',
      parsed: null,
      raw: '',
      importedAt: null,
      setProgramHandle: (handle) => set({ programHandle: handle }),
      setRaw: (raw) => set({ raw }),
      importRaw: (raw) => {
        const parsed = parseScopeText(raw);
        if (parsed.in_scope.length === 0 && parsed.out_of_scope.length === 0) {
          return null;
        }
        set({
          parsed,
          raw,
          importedAt: new Date().toISOString(),
        });
        return parsed;
      },
      clear: () => set({ parsed: null, raw: '', importedAt: null, programHandle: '' }),
    }),
    {
      name: 'cyber-pipeline-scope',
      storage: createJSONStorage(() => customTenantStorage),
      partialize: (state) => ({
        programHandle: state.programHandle,
        parsed: state.parsed,
        raw: state.raw,
        importedAt: state.importedAt,
      }),
    },
  ),
);

let currentTenantId = useAuthStore.getState().user?.tenantId;
useAuthStore.subscribe((state) => {
  const nextTenantId = state.user?.tenantId;
  if (nextTenantId !== currentTenantId) {
    currentTenantId = nextTenantId;
    useScopeStore.persist.rehydrate();
  }
});
