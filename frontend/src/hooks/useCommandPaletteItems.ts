import { useEffect, useSyncExternalStore } from 'react';
import type { SearchableItem } from '@/components/layout/CommandPalette';
import { commandRegistry } from '@/lib/CommandRegistry';

export function registerItem(item: SearchableItem) {
  commandRegistry.register(item);
}

export function unregisterItem(id: string) {
  commandRegistry.unregister(id);
}

export function getAllItems(): SearchableItem[] {
  return commandRegistry.getAll();
}

export function useCommandPaletteItems(items: SearchableItem[]) {
  useEffect(() => {
    commandRegistry.registerMany(items);
    return () => commandRegistry.unregisterMany(items.map(i => i.id));
  }, [items]);
}

export function useRegisterItem(item: SearchableItem | null) {
  useEffect(() => {
    if (!item) return;
    commandRegistry.register(item);
    return () => commandRegistry.unregister(item.id);
  }, [item]);
}

export function useCommandItems(): SearchableItem[] {
  return useSyncExternalStore(
    (cb) => commandRegistry.subscribe(cb),
    () => commandRegistry.getAll(),
  );
}
