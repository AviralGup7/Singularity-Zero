/**
 * Tenant-scoped storage utilities.
 *
 * Extracted from settingsStore/scopeStore to break the circular dependency
 * between authStore and settingsStore. Both stores need tenant-scoped
 * localStorage keys, but previously each imported the other store directly.
 *
 * This module reads the tenant ID from a lightweight accessor that does NOT
 * depend on any Zustand store, avoiding initialization-order hazards.
 */

import { safeStorage, safeSession } from '@/utils/storage';

const AUTH_STORAGE_KEY = 'cyber-pipeline-auth';

/**
 * Read the current tenant ID from sessionStorage (where authStore persists
 * the user object). Falls back to 'tenant-default' when no user is logged
 * in or when sessionStorage is unavailable (private browsing).
 *
 * This is intentionally a plain function, not a store subscription, so it
 * can be called at module-evaluation time without triggering store creation.
 */
export function getCurrentTenantId(): string {
  try {
    const raw = safeSession.get(AUTH_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed?.tenantId) return parsed.tenantId;
    }
  } catch {
    // corrupt storage — fall through
  }
  return 'tenant-default';
}

/**
 * Build a localStorage key scoped to the current tenant.
 * Example: `cyber-pipeline-settings:tenant-abc`
 */
export function scopedKey(baseKey: string): string {
  return `${baseKey}:${getCurrentTenantId()}`;
}

/**
 * Tenant-scopedStorageAdapter — compatible with Zustand's `createJSONStorage`.
 * Reads/writes localStorage with a tenant-suffixed key, falling back to the
 * unsuffixed key for backwards compatibility on read.
 */
export const tenantStorageAdapter = {
  getItem: (name: string): string | null => {
    const tenantId = getCurrentTenantId();
    return localStorage.getItem(`${name}:${tenantId}`) || localStorage.getItem(name);
  },
  setItem: (name: string, value: string): void => {
    const tenantId = getCurrentTenantId();
    localStorage.setItem(`${name}:${tenantId}`, value);
  },
  removeItem: (name: string): void => {
    const tenantId = getCurrentTenantId();
    localStorage.removeItem(`${name}:${tenantId}`);
  },
};

/**
 * Tenant-scoped safeStorage wrapper — uses the safeStorage fallback
 * (memory Map) when localStorage is blocked.
 */
export const tenantSafeStorage = {
  get: (baseKey: string): string | null => {
    return safeStorage.get(scopedKey(baseKey)) || safeStorage.get(baseKey);
  },
  set: (baseKey: string, value: string): void => {
    safeStorage.set(scopedKey(baseKey), value);
  },
  remove: (baseKey: string): void => {
    safeStorage.remove(scopedKey(baseKey));
  },
};
