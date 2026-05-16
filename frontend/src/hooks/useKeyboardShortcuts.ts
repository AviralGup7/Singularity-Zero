import { useEffect, useRef } from 'react';

type ShortcutHandler = () => void;

interface ShortcutDef {
  key: string;
  handler: ShortcutHandler;
  description: string;
  category?: string;
}

interface UseKeyboardShortcutsOptions {
  enabled?: boolean;
  shortcuts: ShortcutDef[];
}

   
let globalShortcuts: ShortcutDef[] = [];
   
let listeners: ((shortcuts: ShortcutDef[]) => void)[] = [];

export function registerGlobalShortcuts(shortcuts: ShortcutDef[]) {
  globalShortcuts = shortcuts;
  listeners.forEach((fn) => fn(shortcuts));
}

export function onGlobalShortcutsChange(fn: (shortcuts: ShortcutDef[]) => void) {
  listeners.push(fn);
  fn(globalShortcuts);
  return () => {
    listeners = listeners.filter((l) => l !== fn);
  };
}

export function useKeyboardShortcuts({ enabled = true, shortcuts }: UseKeyboardShortcutsOptions) {
  const shortcutsRef = useRef(shortcuts);
  const enabledRef = useRef(enabled);

  useEffect(() => {
    shortcutsRef.current = shortcuts;
    enabledRef.current = enabled;
   
  }, [shortcuts, enabled]);

  useEffect(() => {
    if (!enabled) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement) {
        return;
      }
      if (e.target instanceof HTMLElement && e.target.isContentEditable) {
        return;
      }

      const key = e.key.toLowerCase();
      const ctrlOrMeta = e.ctrlKey || e.metaKey;

      for (const shortcut of shortcutsRef.current) {
        const shortcutKey = shortcut.key.toLowerCase();
        if (shortcutKey === key && !(ctrlOrMeta && shortcutKey.includes('+'))) {
          e.preventDefault();
          shortcut.handler();
          return;
        }
        if (ctrlOrMeta && shortcutKey === `cmd+${key}`) {
          e.preventDefault();
          shortcut.handler();
          return;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
   
  }, [enabled]);
}

export function useEscapeToClose(onClose: () => void, enabled = true) {
  useEffect(() => {
    if (!enabled) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
   
  }, [onClose, enabled]);
}
