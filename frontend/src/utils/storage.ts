/**
 * Safe storage utilities to prevent crashes when localStorage/sessionStorage
 * is disabled or inaccessible due to security policies.
 * 
 * Includes an in-memory fallback mechanism to preserve UX when native storage fails.
 */

const memoryStorage = new Map<string, string>();
const memorySession = new Map<string, string>();

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
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
   
      console.warn(`[SafeStorage] Failed to write ${key} to localStorage, using memory fallback:`, e);
      memoryStorage.set(key, value);
      return false; // Still return false to indicate persistence failed, but state is kept in memory
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
