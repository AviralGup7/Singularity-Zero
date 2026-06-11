/**
 * Safe storage utilities to prevent crashes when localStorage/sessionStorage
 * is disabled or inaccessible due to security policies.
 * 
 * Includes an in-memory fallback mechanism to preserve UX when native storage fails.
 */

const memoryStorage = new Map<string, string>();
const memorySession = new Map<string, string>();

const MAX_STORAGE_ITEM_BYTES = 512 * 1024; // 512 KB per item
const MAX_STORAGE_TOTAL_BYTES = 5 * 1024 * 1024; // 5 MB total

function estimateStorageSize(): number {
  let total = 0;
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key) {
        const val = localStorage.getItem(key);
        total += (key.length + (val?.length ?? 0)) * 2; // UTF-16
      }
    }
  } catch { /* ignore */ }
  return total;
}

export const safeStorage = {
  get: (key: string): string | null => {
    try {
      return localStorage.getItem(key);
    } catch (e) {
      console.warn(`[SafeStorage] Failed to read ${key} from localStorage, using memory fallback:`, e);
      return memoryStorage.get(key) || null;
    }
  },
  set: (key: string, value: string): boolean => {
    if (value.length * 2 > MAX_STORAGE_ITEM_BYTES) {
      console.warn(`[SafeStorage] Refusing to write ${key}: item exceeds ${MAX_STORAGE_ITEM_BYTES / 1024}KB limit`);
      return false;
    }
    try {
      const currentSize = estimateStorageSize();
      const itemSize = (key.length + value.length) * 2;
      if (currentSize + itemSize > MAX_STORAGE_TOTAL_BYTES) {
        console.warn(`[SafeStorage] Storage quota near limit, attempting cleanup`);
        safeStorage._evictOldest();
      }
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
      console.warn(`[SafeStorage] Failed to write ${key} to localStorage, using memory fallback:`, e);
      memoryStorage.set(key, value);
      return false;
    }
  },
  remove: (key: string): void => {
    try {
      localStorage.removeItem(key);
    } catch (e) {
   
      console.warn(`[SafeStorage] Failed to remove ${key} from localStorage, removing from memory fallback:`, e);
    } finally {
      memoryStorage.delete(key);
    }
  },
  clear: (): void => {
    try {
      localStorage.clear();
    } catch (e) {
      console.warn('[SafeStorage] Failed to clear localStorage, clearing memory fallback:', e);
    } finally {
      memoryStorage.clear();
    }
  },
  _evictOldest: (): void => {
    try {
      if (localStorage.length > 0) {
        const oldestKey = localStorage.key(0);
        if (oldestKey) localStorage.removeItem(oldestKey);
      }
    } catch { /* ignore */ }
  }
};

export const safeSession = {
  get: (key: string): string | null => {
    try {
      return sessionStorage.getItem(key);
    } catch (e) {
   
      console.warn(`[SafeSession] Failed to read ${key} from sessionStorage, using memory fallback:`, e);
      return memorySession.get(key) || null;
    }
  },
  set: (key: string, value: string): boolean => {
    try {
      sessionStorage.setItem(key, value);
      return true;
    } catch (e) {
   
      console.warn(`[SafeSession] Failed to write ${key} to sessionStorage, using memory fallback:`, e);
      memorySession.set(key, value);
      return false;
    }
  },
  remove: (key: string): void => {
    try {
      sessionStorage.removeItem(key);
    } catch (e) {
   
      console.warn(`[SafeSession] Failed to remove ${key} from sessionStorage, removing from memory fallback:`, e);
    } finally {
      memorySession.delete(key);
    }
  },
  clear: (): void => {
    try {
      sessionStorage.clear();
    } catch (e) {
   
      console.warn('[SafeSession] Failed to clear sessionStorage, clearing memory fallback:', e);
    } finally {
      memorySession.clear();
    }
  }
};
