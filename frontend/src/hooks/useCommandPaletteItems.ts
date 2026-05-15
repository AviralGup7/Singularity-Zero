import { useEffect, useCallback } from 'react';
import type { SearchableItem } from '@/components/CommandPalette';

interface _RegisteredItem {
  id: string;
  item: SearchableItem;
}

const itemRegistry = new Map<string, SearchableItem>();

export function registerItem(item: SearchableItem) {
  itemRegistry.set(item.id, item);
}

export function unregisterItem(id: string) {
  itemRegistry.delete(id);
}

export function getAllItems(): SearchableItem[] {
  return Array.from(itemRegistry.values());
}

export function useCommandPaletteItems(items: SearchableItem[]) {
  useEffect(() => {
    for (const item of items) {
      itemRegistry.set(item.id, item);
    }
    return () => {
      for (const item of items) {
        itemRegistry.delete(item.id);
      }
    };
  }, [items]);

  const allItems = useCallback(() => {
    return Array.from(itemRegistry.values());
  }, []);

  return { allItems };
}

export function useRegisterItem(item: SearchableItem | null) {
  useEffect(() => {
    if (!item) return;
    itemRegistry.set(item.id, item);
    return () => {
      itemRegistry.delete(item.id);
    };
  }, [item]);
}
