import { useEffect, useRef } from 'react';
import { shouldIgnoreGlobalShortcut } from '@/utils/findingTime';

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

const MODIFIER_TOKENS = new Set(['ctrl', 'control', 'cmd', 'meta', 'alt', 'option', 'shift']);

/** Match a shortcut spec like "a", "escape", "ctrl+k", or "cmd+shift+p". */
export function shortcutEventMatches(shortcutKey: string, e: KeyboardEvent): boolean {
  const tokens = shortcutKey.toLowerCase().split('+').map((part) => part.trim()).filter(Boolean);
  if (tokens.length === 0) return false;
  const keyToken = tokens[tokens.length - 1];
  const mods = new Set(tokens.slice(0, -1));
  const wantCtrl = mods.has('ctrl') || mods.has('control') || mods.has('cmd') || mods.has('meta');
  const wantAlt = mods.has('alt') || mods.has('option');
  const wantShift = mods.has('shift');
  if ([...mods].some((token) => !MODIFIER_TOKENS.has(token))) return false;
  const hasCtrl = e.ctrlKey || e.metaKey;
  if (wantCtrl !== hasCtrl) return false;
  if (wantAlt !== e.altKey) return false;
  if (wantShift !== e.shiftKey) return false;
  return e.key.toLowerCase() === keyToken;
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
      if (shouldIgnoreGlobalShortcut(e.target)) return;

      for (const shortcut of shortcutsRef.current) {
        if (!shortcutEventMatches(shortcut.key, e)) continue;
        e.preventDefault();
        shortcut.handler();
        return;
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
      if (e.key !== 'Escape') return;
      // Dialogs and overlays must close from search fields too.
      e.preventDefault();
      onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
   
  }, [onClose, enabled]);
}
