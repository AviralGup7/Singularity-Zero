import { create } from 'zustand';
import { safeStorage } from '@/utils/storage';
import type { DensityMode, FontSize, DisplayState, DisplayUpdater } from '@/context/DisplayContext';

const defaultDisplay: DisplayState = {
  density: 'comfortable',
  fontSize: 'medium',
  animations: true,
  gridBackground: true,
  reduceMotion: false,
  highContrast: false,
  focusIndicators: true,
  screenReaderOptimizations: false,
  systemReducedMotion: false,
  constrainedDevice: false,
};

const SIDEBAR_STORAGE_KEY = 'cyber-pipeline-sidebar';
const WORKFLOW_MODE_STORAGE_KEY = 'cyber-pipeline-workflow-mode';
const defaultSidebar = { collapsed: false };

export type WorkflowMode = 'pentest' | 'appsec';

export function parseWorkflowMode(raw: string | null): WorkflowMode | null {
  if (raw === 'pentest' || raw === 'appsec') return raw;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed === 'pentest' || parsed === 'appsec') return parsed;
  } catch {
    return null;
  }
  return null;
}

function getInitialWorkflowMode(): WorkflowMode {
  return parseWorkflowMode(safeStorage.get(WORKFLOW_MODE_STORAGE_KEY)) ?? 'appsec';
}

function getInitialSidebar(): { collapsed: boolean } {
  const stored = safeStorage.get(SIDEBAR_STORAGE_KEY);
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      if (typeof parsed === 'object' && parsed !== null && typeof parsed.collapsed === 'boolean') {
        return { collapsed: parsed.collapsed };
      }
    } catch (err) {
      console.warn('[display] ignored corrupt sidebar storage', err);
    }
  }
  return defaultSidebar;
}

const persistSidebar = (state: { collapsed: boolean }) => {
  safeStorage.set(SIDEBAR_STORAGE_KEY, JSON.stringify(state));
};

function detectSystemReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function detectConstrainedDevice(): boolean {
  if (typeof navigator === 'undefined') {
    return false;
  }
  const cores = typeof navigator.hardwareConcurrency === 'number' ? navigator.hardwareConcurrency : 8;
  const memoryValue = (navigator as Navigator & { deviceMemory?: number }).deviceMemory;
  const memory = typeof memoryValue === 'number' ? memoryValue : 8;
  return cores <= 2 || memory <= 2;
}

function getInitialDisplay(): DisplayState {
  const stored = safeStorage.get('cyber-pipeline-display');
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      return {
        ...defaultDisplay,
        ...parsed,
        systemReducedMotion: detectSystemReducedMotion(),
        constrainedDevice: detectConstrainedDevice(),
      };
    } catch (err) {
      console.warn('[display] ignored corrupt display storage', err);
    }
  }
  return {
    ...defaultDisplay,
    systemReducedMotion: detectSystemReducedMotion(),
    constrainedDevice: detectConstrainedDevice(),
  };
}

const applyDisplaySideEffects = (display: DisplayState) => {
  if (typeof window === 'undefined') return;
  document.documentElement.setAttribute('data-density', display.density);
  document.documentElement.setAttribute('data-font-size', display.fontSize);
  document.documentElement.setAttribute('data-animations', display.animations ? 'true' : 'false');
  document.documentElement.setAttribute('data-grid-bg', display.gridBackground ? 'true' : 'false');
  document.documentElement.setAttribute('data-reduce-motion', display.reduceMotion ? 'true' : 'false');
  document.documentElement.setAttribute('data-system-reduced-motion', display.systemReducedMotion ? 'true' : 'false');
  document.documentElement.setAttribute('data-constrained-device', display.constrainedDevice ? 'true' : 'false');
  document.documentElement.setAttribute('data-accessibility',
    display.highContrast ? 'high-contrast' :
    display.reduceMotion ? 'reduce-motion' :
    display.focusIndicators ? 'focus-indicators' : 'default'
  );
  safeStorage.set('cyber-pipeline-display', JSON.stringify(display));
};

/** Global display preferences store. Handles density, font size, animations, accessibility, sidebar, and workflow mode. */
export interface DisplayStore {
  /** Current display state (density, font size, animations, etc.) */
  display: DisplayState;
  /** Actions to mutate individual display properties */
  updater: DisplayUpdater;
  /**
   * Layout-level UI state that is persisted across reloads but is *not*
   * part of the `DisplayState` (which is bound to the legacy DisplayContext
   * contract for theme/density/accessibility prefs). The sidebar collapse
   * state belongs here because it is a layout preference that should
   * survive a page reload — fixing the R3 gap where AppLayout used
   * `useState(false)` and reset on every navigation.
   */
  sidebarCollapsed: boolean;
  /** Persist and set the sidebar collapsed state. */
  setSidebarCollapsed: (collapsed: boolean) => void;
  /** Toggle the sidebar between collapsed and expanded. */
  toggleSidebarCollapsed: () => void;
  /**
   * Workflow mode (pentest vs appsec). Used to gate telemetry-heavy
   * features like live terminal streams, presence indicators, and 3D
   * views so that AppSec auditors can opt into a quieter surface.
   */
  workflowMode: WorkflowMode;
  /** Persist and set the active workflow mode. */
  setWorkflowMode: (mode: WorkflowMode) => void;
}

export const useDisplayStore = create<DisplayStore>((set, get) => {
  const initialDisplay = getInitialDisplay();
  const initialSidebar = getInitialSidebar();

  // Apply initial side effects on load
  applyDisplaySideEffects(initialDisplay);

  const updateDisplay = (partial: Partial<DisplayState>) => {
    set((state) => {
      const nextDisplay = { ...state.display, ...partial };
      applyDisplaySideEffects(nextDisplay);
      return { display: nextDisplay };
    });
  };

  return {
    display: initialDisplay,
    updater: {
      /** Merge a partial `DisplayState` into the current display settings. */
      updateDisplay,
      /** Set the UI density mode (compact / comfortable / spacious). */
      setDensity: (density: DensityMode) => updateDisplay({ density }),
      /** Set the base font size (small / medium / large). */
      setFontSize: (fontSize: FontSize) => updateDisplay({ fontSize }),
      /** Enable or disable UI animations globally. */
      setAnimations: (animations: boolean) => updateDisplay({ animations }),
      /** Show or hide the background grid pattern. */
      setGridBackground: (gridBackground: boolean) => updateDisplay({ gridBackground }),
      /** Request reduced motion from animation components. */
      setReduceMotion: (reduceMotion: boolean) => updateDisplay({ reduceMotion }),
      /** Toggle high-contrast mode for accessibility. */
      setHighContrast: (highContrast: boolean) => updateDisplay({ highContrast }),
      /** Enable or disable visible focus indicators for keyboard navigation. */
      setFocusIndicators: (focusIndicators: boolean) => updateDisplay({ focusIndicators }),
      /** Optimize UI for screen reader compatibility. */
      setScreenReaderOptimizations: (screenReaderOptimizations: boolean) => updateDisplay({ screenReaderOptimizations }),
    },
    sidebarCollapsed: initialSidebar.collapsed,
    /** Collapse or expand the sidebar and persist the choice. */
    setSidebarCollapsed: (collapsed: boolean) => {
      persistSidebar({ collapsed });
      set({ sidebarCollapsed: collapsed });
    },
    /** Toggle sidebar collapsed state and persist it. */
    toggleSidebarCollapsed: () => {
      const next = !get().sidebarCollapsed;
      persistSidebar({ collapsed: next });
      set({ sidebarCollapsed: next });
    },
    workflowMode: getInitialWorkflowMode(),
    /** Switch between pentest and appsec workflow mode. Persisted across reloads. */
    setWorkflowMode: (mode: WorkflowMode) => {
      safeStorage.set(WORKFLOW_MODE_STORAGE_KEY, JSON.stringify(mode));
      set({ workflowMode: mode });
    },
  };
});

// Setup dynamic media query listener for system reduced motion
if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
  const media = window.matchMedia('(prefers-reduced-motion: reduce)');
  const handleMediaChange = () => {
    useDisplayStore.getState().updater.updateDisplay({
      systemReducedMotion: media.matches,
    });
  };
  media.addEventListener('change', handleMediaChange);
}
