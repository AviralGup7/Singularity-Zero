import axios from 'axios';
import type { AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios';
import { z } from 'zod';
import { apiCache } from './cache';
import i18n from '../i18n';
import { dispatchToast } from '../lib/toastDispatcher';
import { captureException } from '../utils/errorTracker';
import { withRetry } from './retry';
import { getStreamToken } from './streamAuth';
import { useAuthStore } from '../stores/authStore';
import { flattenApiDetail, parseRetryAfterMs } from './contract';

declare module 'axios' {
  interface InternalAxiosRequestConfig {
    metadata?: { startTime?: number; ttl?: number };
    schema?: z.ZodSchema;
  }
  interface AxiosRequestConfig {
    metadata?: { startTime?: number; ttl?: number };
    schema?: z.ZodSchema;
  }
}

const API_BASE = import.meta.env.VITE_API_BASE || '';

// Build-time validation: warn if API_BASE is not set in production
if (!import.meta.env.DEV && !import.meta.env.VITE_API_BASE) {
  console.warn(
    '[API] VITE_API_BASE is not set. API calls will use the same origin. ' +
    'Set VITE_API_BASE in your .env for production builds.'
  );
}

export const MAX_RESPONSE_SIZE_BYTES = 10 * 1024 * 1024;
const ALLOWED_PROTOCOLS = ['http:', 'https:'];
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

export function isLoopbackHostname(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');
  return LOOPBACK_HOSTS.has(host) || host.endsWith('.localhost');
}

export function measureResponseBytes(data: unknown, contentLengthHeader?: string): number {
  if (contentLengthHeader) {
    const listed = Number.parseInt(String(contentLengthHeader), 10);
    if (Number.isFinite(listed) && listed >= 0) return listed;
  }
  if (data == null) return 0;
  if (typeof data === 'string') {
    return typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(data).length : data.length;
  }
  if (typeof ArrayBuffer !== 'undefined' && data instanceof ArrayBuffer) return data.byteLength;
  if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(data)) return data.byteLength;
  if (typeof Blob !== 'undefined' && data instanceof Blob) return data.size;
  try {
    return JSON.stringify(data).length;
  } catch {
    return MAX_RESPONSE_SIZE_BYTES + 1;
  }
}

// Request deduplication: prevent duplicate concurrent GET requests for the same URL
const pendingRequests = new Map<string, Promise<unknown>>();

function _deduplicateKey(url: string, options?: CachedRequestOptions): string {
  return JSON.stringify({
    url,
    params: options?.params ?? null,
    timeout: options?.timeout ?? null,
    ttl: options?.ttl ?? null,
    bypassCache: options?.bypassCache ?? false,
    schema: options?.schema ? String(options.schema.description ?? options.schema.constructor.name) : null,
  });
}

export function validateRequestUrl(url: string, baseURL?: string): boolean {
  try {
    const base = baseURL || (typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
    const resolved = new URL(url, base);
    // Always validate protocol, even in dev mode
    if (!ALLOWED_PROTOCOLS.includes(resolved.protocol)) return false;
    if (typeof window !== 'undefined' && resolved.host === window.location.host) {
      return true;
    }
    if (import.meta.env.DEV) {
      return isLoopbackHostname(resolved.hostname);
    }
    if (isLoopbackHostname(resolved.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

let csrfToken: string | null = null;
let csrfPending: Promise<string | null> | null = null;

async function fetchCsrfToken(): Promise<string | null> {
  if (csrfToken) return csrfToken;
  if (csrfPending) return csrfPending;
  csrfPending = (async () => {
    try {
      // GET is CSRF-safe, so this cannot recurse into fetchCsrfToken.
      const response = await apiClient.get<{ csrf_token: string }>('/api/csrf-token', {
        withCredentials: true,
        timeout: 5000,
      });
      const token = response.data?.csrf_token;
      csrfToken = typeof token === 'string' && token.trim() ? token : null;
      return csrfToken;
    } catch {
      return null;
    } finally {
      csrfPending = null;
    }
  })();
  return csrfPending;
}

function generateRequestId(): string {
  return `req-${crypto.randomUUID()}`;
}

export class ApiError extends Error {
  status?: number;
  original: unknown;
  retryAfterMs?: number;
  code?: string;

  constructor(message: string, status?: number, original?: unknown, extras?: { retryAfterMs?: number; code?: string }) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.original = original;
    this.retryAfterMs = extras?.retryAfterMs;
    this.code = extras?.code;
    Object.setPrototypeOf(this, ApiError.prototype);
  }
}

export const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest'
  },
});

apiClient.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    const token = getStreamToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    config.headers['X-Request-ID'] = generateRequestId();
    config.metadata = { startTime: Date.now() };

    if (config.url && !validateRequestUrl(config.url, config.baseURL)) {
      return Promise.reject(new Error(i18n.t('errors.invalidRequestUrl')));
    }

    const user = useAuthStore.getState().user;
    if (user?.tenantId) {
      config.headers['X-Tenant-ID'] = user.tenantId;
    }
    if (user?.organizationId) {
      config.headers['X-Organization-ID'] = user.organizationId;
    }

    if (config.method && ['post', 'put', 'delete', 'patch'].includes(config.method) && config.url) {
      apiCache.markMutationStart(config.url);
    }

    if (config.method && ['post', 'put', 'delete', 'patch'].includes(config.method)) {
      const token = csrfToken ?? await fetchCsrfToken();
      if (token) {
        config.headers['X-CSRF-Token'] = token;
      } else if (!String(config.headers.Authorization ?? '').toLowerCase().startsWith('bearer ')) {
        // Cookie/demo sessions are CSRF-vulnerable. Bearer-only calls are
        // exempt on the server when no csrf cookie is present.
        return Promise.reject(new ApiError(i18n.t('errors.csrfUnavailable'), 403));
      }
    }

    return config;
  },
  (error) => {
    captureException(error instanceof Error ? error : new Error(String(error)), {
      component: 'apiClient',
      action: 'request',
    });
    return Promise.reject(error);
  }
);

apiClient.interceptors.response.use(
  (response) => {
    const responseTime = Date.now() - (response.config.metadata?.startTime ?? Date.now());
     
    if (response.headers['content-length']) {
      const size = parseInt(String(response.headers['content-length']), 10);
      if (size > MAX_RESPONSE_SIZE_BYTES) {
        captureException(new Error(`Response too large: ${size} bytes`), {
          component: 'apiClient',
          action: 'response_size',
        });
        return Promise.reject(new Error(i18n.t('errors.responseTooLarge')));
      }
    }

    if (response.config.method && response.config.url) {
      apiCache.markMutationEnd(response.config.url);
      apiCache.invalidateOnMutation(response.config.method, response.config.url);
    }

    const schema = response.config.schema;
    if (schema) {
      const result = schema.safeParse(response.data);
      if (!result.success) {
        const issues = result.error.issues.slice(0, 8).map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        }));
        if (import.meta.env.DEV) {
          console.error(`[API CONTRACT VIOLATION] ${response.config.method?.toUpperCase()} ${response.config.url}`, {
            errors: issues,
            received: response.data,
          });
          dispatchToast('API Contract Violation Detected (check console)', 'warning');
        }
        captureException(
          new Error(`API contract violation: ${response.config.method?.toUpperCase()} ${response.config.url}`),
          { component: 'apiClient', action: 'schema_validation', metadata: { errors: issues } }
        );
        return Promise.reject(new Error(i18n.t('errors.schemaViolation')));
      }
    }

    if (import.meta.env.DEV) {
      console.debug(`[API] ${response.config.method?.toUpperCase()} ${response.config.url} - ${responseTime}ms`);
    }
     
    if (response.config.method === 'get') {
      const key = apiCache.generateKey(response.config.url ?? '', response.config.params);
   
      const ttlHeader = response.headers?.['x-cache-ttl'];
      const ttl = response.config.metadata?.ttl ?? (ttlHeader ? Number(ttlHeader) : undefined);
      if (ttl !== undefined) {
        apiCache.set(key, response.data, ttl);
      }
    }
     
    return response;
  },
  (error) => {
    // Fix S0-3: Mark mutation end even on error
    if (error.config?.method && error.config?.url) {
      apiCache.markMutationEnd(error.config.url);
    }

    if (axios.isCancel(error)) {
      return Promise.reject(error);
    }
    const responseTime = error.config?.metadata?.startTime
      ? Date.now() - error.config.metadata.startTime
      : null;
       
    if (import.meta.env.DEV && responseTime !== null) {
      console.debug(`[API] ${error.config?.method?.toUpperCase()} ${error.config?.url} - ${responseTime}ms (error)`);
    }

    let message = i18n.t('errors.unexpectedError');
    const status = error.response?.status;
    const payload = error.response?.data;
    const serverDetail =
      flattenApiDetail(payload?.detail) ||
      flattenApiDetail(payload?.error) ||
      flattenApiDetail(payload);
    const retryAfterMs = parseRetryAfterMs(error.response?.headers);

    if (status === 404 && error.config?.url) {
      console.warn(`[404 DEBUG] URL=${error.config.url} status=${status} detail=${JSON.stringify(error.response?.data)}`);
    }

    if (status && status < 500) {
      message = serverDetail || error.message || i18n.t('errors.unexpectedError');
    } else if (status && status >= 500) {
      message = i18n.t('errors.internalSystemError');
    } else if (!error.response) {
      message = i18n.t('errors.meshOffline');
    }

    // Auto-Toast for critical failures is opt-in. The `__apiAutoToast`
    // flag is set on the request config by callers that want the
    // hard-wired toast UX (e.g. login, token refresh). All other calls
    // get the wrapped error returned to the caller, which can choose
    // to surface a custom message in its own UI.
    if (error.config?.__apiAutoToast) {
      if (status === 401) {
        dispatchToast(i18n.t('errors.sessionExpired'), 'error');
      } else if (status === 429) {
        dispatchToast(i18n.t('errors.rateLimitReached'), 'warning');
      }
    }

    const wrapped = new ApiError(message, status, error, {
      retryAfterMs: status === 429 ? retryAfterMs : undefined,
      code: typeof payload?.code === 'string' ? payload.code : undefined,
    });
    captureException(wrapped, {
      component: 'apiClient',
      action: 'response',
      metadata: { status, url: error.config?.url },
    });
    return Promise.reject(wrapped);
  }
);

interface CachedRequestOptions {
  signal?: AbortSignal;
  ttl?: number;
  bypassCache?: boolean;
  params?: Record<string, unknown>;
  timeout?: number;
  schema?: z.ZodSchema;
}

export async function cachedGet<T>(url: string, options?: CachedRequestOptions): Promise<T> {
  const key = apiCache.generateKey(url, options?.params);
  const pendingKey = _deduplicateKey(url, options);

  const shouldBypass = options?.bypassCache || apiCache.shouldBypassForMutation(url);

  if (!shouldBypass) {
    const cached = apiCache.get<T>(key);
    if (cached !== null && !apiCache.isStale(key)) {
      return cached;
    }
    // Stale-while-revalidate: return stale data immediately, refetch in background
    if (cached !== null && apiCache.isStale(key)) {
      withRetry(() =>
        apiClient.get<T>(url, { 
          signal: options?.signal, 
          params: options?.params, 
          timeout: options?.timeout,
          schema: options?.schema,
          ...(options?.ttl ? { metadata: { ttl: options.ttl } } : {})
        } as AxiosRequestConfig).then((res) => {
          apiCache.set(key, res.data, options?.ttl);
          return res.data;
        })
      ).catch(() => {
        // Background revalidation failed — stale data remains in cache
      });
      return cached;
    }
  }

  const existingPending = pendingRequests.get(pendingKey) as Promise<T> | undefined;
  if (existingPending) {
    return existingPending;
  }

  const requestPromise = withRetry(() =>
    apiClient.get<T>(url, { 
      signal: options?.signal, 
      params: options?.params, 
      timeout: options?.timeout,
      schema: options?.schema,
      ...(options?.ttl ? { metadata: { ttl: options.ttl } } : {})
    } as AxiosRequestConfig).then((res) => res.data)
  ).finally(() => {
    pendingRequests.delete(pendingKey);
  });

  pendingRequests.set(pendingKey, requestPromise);
  return requestPromise;
}

export async function cachedPost<T>(url: string, body?: unknown, options?: CachedRequestOptions): Promise<T> {
  const res = await apiClient.post<T>(url, body, { 
    signal: options?.signal, 
    params: options?.params, 
    timeout: options?.timeout,
    schema: options?.schema
  } as AxiosRequestConfig).then((res) => res.data);
  return res;
}
