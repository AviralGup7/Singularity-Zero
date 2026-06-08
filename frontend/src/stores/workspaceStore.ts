import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { safeStorage } from '@/utils/storage';

export interface WorkspaceState {
  activeJobId: string | null;
  activeFindingId: string | null;
  lastTargetUrl: string;
  selectedSeverity: string[];
  appliedFilters: Record<string, string>;
  workspaceName: string;
}

interface WorkspaceStore {
  workspaces: WorkspaceState[];
  activeWorkspaceIndex: number;
  setActiveWorkspace: (index: number) => void;
  saveWorkspace: (name: string) => void;
  deleteWorkspace: (index: number) => void;
  updateWorkspaceState: (partial: Partial<WorkspaceState>) => void;
  getActiveWorkspace: () => WorkspaceState;
}

const defaultWorkspace = (): WorkspaceState => ({
  activeJobId: null,
  activeFindingId: null,
  lastTargetUrl: '',
  selectedSeverity: [],
  appliedFilters: {},
  workspaceName: 'Default',
});

export const useWorkspaceStore = create<WorkspaceStore>()(
  persist(
    (set, get) => ({
      workspaces: [defaultWorkspace()],
      activeWorkspaceIndex: 0,

      setActiveWorkspace: (index: number) => {
        const workspaces = get().workspaces;
        if (index >= 0 && index < workspaces.length) {
          set({ activeWorkspaceIndex: index });
        }
      },

      saveWorkspace: (name: string) => {
        const current = get().getActiveWorkspace();
        set((state) => ({
          workspaces: [...state.workspaces, { ...current, workspaceName: name }],
          activeWorkspaceIndex: state.workspaces.length,
        }));
      },

      deleteWorkspace: (index: number) => {
        set((state) => {
          const workspaces = state.workspaces.filter((_, i) => i !== index);
          const activeIndex = state.activeWorkspaceIndex >= workspaces.length ? 0 : state.activeWorkspaceIndex;
          return { workspaces, activeWorkspaceIndex: activeIndex };
        });
      },

      updateWorkspaceState: (partial: Partial<WorkspaceState>) => {
        set((state) => {
          const workspaces = [...state.workspaces];
          const idx = state.activeWorkspaceIndex;
          if (idx >= 0 && idx < workspaces.length) {
            workspaces[idx] = { ...workspaces[idx], ...partial };
          }
          return { workspaces };
        });
      },

      getActiveWorkspace: () => {
        const state = get();
        return state.workspaces[state.activeWorkspaceIndex] ?? defaultWorkspace();
      },
    }),
    {
      name: 'cyber-pipeline-workspace',
      storage: {
        getItem: (name) => {
          const val = safeStorage.get(name);
          return val ?? null;
        },
        setItem: (name, value) => {
          safeStorage.set(name, value);
        },
        removeItem: (name) => {
          safeStorage.remove(name);
        },
      },
    }
  )
);
