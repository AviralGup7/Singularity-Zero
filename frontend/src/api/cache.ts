interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
  stale?: boolean;
}

interface CacheConfig {
  defaultTTL: number;
  maxEntries: number;
  staleWhileRevalidate: boolean;
}

const DEFAULT_CONFIG: CacheConfig = {
  defaultTTL: 30000,
  maxEntries: 100,
  staleWhileRevalidate: true,
};

class ApiCache {
  private cache = new Map<string, CacheEntry<unknown>>();
  private config: CacheConfig;

  constructor(config?: Partial<CacheConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  private stableStringify(val: unknown): string {
    if (val === null || typeof val !== 'object' || Array.isArray(val)) {
      return JSON.stringify(val);
    }
    const obj = val as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys.map(k => {
   
      const value = obj[k as keyof typeof obj];
      return `"${k}":${this.stableStringify(value)}`;
    });
    return `{${parts.join(',')}}`;
  }

  generateKey(url: string, params?: Record<string, unknown>): string {
    if (!params) return url;
    const sortedParams = Object.entries(params)
   
      .sort(([a], [b]) => a.localeCompare(b))
   
      .map(([key, val]) => {
        return `${key}=${this.stableStringify(val)}`;
      })
      .join('&');
    return `${url}?${sortedParams}`;
  }

  get<T>(key: string): T | null {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined;
    if (!entry) return null;

    // Promote key (LRU)
    this.cache.delete(key);
    this.cache.set(key, entry);

    const age = Date.now() - entry.timestamp;
    if (age < entry.ttl) {
      return entry.data;
    }

    if (this.config.staleWhileRevalidate) {
      entry.stale = true;
      return entry.data;
    }

    this.cache.delete(key);
    return null;
  }

  set<T>(key: string, data: T, ttl?: number): void {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.config.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl: ttl ?? this.config.defaultTTL,
      stale: false,
    });
  }

  invalidate(key: string): void {
    this.cache.delete(key);
  }

  invalidatePrefix(prefix: string): void {
    for (const key of Array.from(this.cache.keys())) {
      if (key.startsWith(prefix)) {
        this.cache.delete(key);
      }
    }
  }

  invalidateAll(): void {
    this.cache.clear();
  }

  isStale(key: string): boolean {
    const entry = this.cache.get(key);
    return entry?.stale ?? false;
  }

  invalidateOnMutation(method: string, url: string): void {
    const upperMethod = method.toUpperCase();
   
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(upperMethod)) {
   
      const basePath = url.split('?')[0].split('/').slice(0, -1).join('/');
      if (basePath) {
        this.invalidatePrefix(basePath);
      }
   
      this.invalidatePrefix(url.split('?')[0]);
    }
  }

  setConfig(config: Partial<CacheConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

export const apiCache = new ApiCache();

export function configureCache(config: Partial<CacheConfig>): void {
  apiCache.setConfig(config);
}

export default apiCache;
