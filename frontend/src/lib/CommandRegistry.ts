import type { SearchableItem } from '@/components/layout/CommandPalette';

type Listener = (items: SearchableItem[]) => void;

class CommandRegistry {
  private items = new Map<string, SearchableItem>();
  private listeners = new Set<Listener>();

  register(item: SearchableItem) {
    this.items.set(item.id, item);
    this.notify();
  }

  registerMany(items: SearchableItem[]) {
    for (const item of items) {
      this.items.set(item.id, item);
    }
    this.notify();
  }

  unregister(id: string) {
    this.items.delete(id);
    this.notify();
  }

  unregisterMany(ids: string[]) {
    for (const id of ids) {
      this.items.delete(id);
    }
    this.notify();
  }

  getAll(): SearchableItem[] {
    return Array.from(this.items.values());
  }

  subscribe(listener: Listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify() {
    const snapshot = this.getAll();
    for (const listener of this.listeners) {
      listener(snapshot);
    }
  }
}

export const commandRegistry = new CommandRegistry();
