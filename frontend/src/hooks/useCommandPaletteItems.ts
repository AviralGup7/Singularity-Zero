import { useEffect, useRef, useSyncExternalStore } from 'react';
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

export function itemsKey(items: Array<{ id?: string }>): string {
  return items.map((item) => String(item.id ?? '').trim()).filter(Boolean).join(',');
}

export function useCommandPaletteItems(items: SearchableItem[]) {
  const prevKeyRef = useRef<string>('');
  
  useEffect(() => {
    const currentKey = itemsKey(items);
    const prevKey = prevKeyRef.current;
    
    // Only re-register if the item IDs actually changed
    if (currentKey !== prevKey) {
      // Unregister previous items
      if (prevKey) {
        const prevIds = prevKey.split(',').filter(Boolean);
        prevIds.forEach(id => commandRegistry.unregister(id));
      }
      // Register new items
      if (items.length > 0) {
        commandRegistry.registerMany(items);
      }
      prevKeyRef.current = currentKey;
    }
    
    return () => {
      const ids = currentKey.split(',').filter(Boolean);
      ids.forEach(id => commandRegistry.unregister(id));
      prevKeyRef.current = '';
    };
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
