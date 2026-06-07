import axios from 'axios';
import type { AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios';
import { z } from 'zod';
import { apiCache } from './cache';
import { dispatchToast } from '../lib/toastDispatcher';
import { captureException } from '../utils/errorTracker';
import { withRetry } from './retry';
import { getStreamToken } from './streamAuth';
import { useAuthStore } from '../stores/authStore';

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

function generateRequestId(): string {
  return `req-${crypto.randomUUID()}`;
}

export class ApiError extends Error {
  status?: number;
  original: unknown;

  constructor(message: string, status?: number, original?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.original = original;
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
  (config: InternalAxiosRequestConfig) => {
    const token = getStreamToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    config.headers['X-Request-ID'] = generateRequestId();
    config.metadata = { startTime: Date.now() };

    const user = useAuthStore.getState().user;
    if (user?.tenantId) {
      config.headers['X-Tenant-ID'] = user.tenantId;
    }
    if (user?.organizationId) {
      config.headers['X-Organization-ID'] = user.organizationId;
    }

    // Fix S0-3: Mark mutation start to prevent stale reads during mutations
    if (config.method && ['post', 'put', 'delete', 'patch'].includes(config.method.toLowerCase()) && config.url) {
      apiCache.markMutationStart(config.url);
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
     
    // Fix S0-3: Mark mutation end
    if (response.config.method && response.config.url) {
      apiCache.markMutationEnd(response.config.url);
      apiCache.invalidateOnMutation(response.config.method, response.config.url);
    }

    // --- Overhaul: Contract Guard Validation ---
    const schema = response.config.schema;
    if (schema) {
      const result = schema.safeParse(response.data);
      if (!result.success) {
        if (import.meta.env.DEV) {
          console.error(`[API CONTRACT VIOLATION] ${response.config.method?.toUpperCase()} ${response.config.url}`, {
            errors: result.error.format(),
            received: response.data
          });
          dispatchToast('API Contract Violation Detected (check console)', 'warning');
        }
      }
    }

    if (import.meta.env.DEV) {
   
      console.debug(`[API] ${response.config.method?.toUpperCase()} ${response.config.url} - ${responseTime}ms`);
    }
     
    if (response.config.method === 'get') {
      const key = apiCache.generateKey(response.config.url ?? '', response.config.params);
   
      const ttlHeader = response.headers?.['x-cache-ttl'];
      // Use TTL from metadata (passed from cachedGet) or from header
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
      captureException(error instanceof Error ? error : new Error(String(error)), {
        component: 'apiClient',
        action: 'cancel',
      });
      return Promise.reject(error);
    }
    const responseTime = error.config?.metadata?.startTime
      ? Date.now() - error.config.metadata.startTime
      : null;
       
    if (import.meta.env.DEV && responseTime !== null) {
   
      console.debug(`[API] ${error.config?.method?.toUpperCase()} ${error.config?.url} - ${responseTime}ms (error)`);
    }

    let message = 'An unexpected error occurred';
    const status = error.response?.status;
    const serverDetail = error.response?.data?.detail;

    if (status && status < 500) {
      message = serverDetail || error.message || 'An unexpected error occurred';
    } else if (status && status >= 500) {
      message = 'Internal System Error. Retrying...';
    } else if (!error.response) {
      message = 'Mesh offline - check connection.';
    }

    // Auto-Toast for critical failures is opt-in. The `__apiAutoToast`
    // flag is set on the request config by callers that want the
    // hard-wired toast UX (e.g. login, token refresh). All other calls
    // get the wrapped error returned to the caller, which can choose
    // to surface a custom message in its own UI.
    if (error.config?.__apiAutoToast) {
      if (status === 401) {
        dispatchToast('Session expired.', 'error');
      } else if (status === 429) {
        dispatchToast('Rate limit reached.', 'warning');
      }
    }

    const wrapped = new ApiError(message, status, error);
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

  // Fix S0-3: Automatically bypass cache if a mutation is pending for this URL
  const shouldBypass = options?.bypassCache || apiCache.shouldBypassForMutation(url);

  if (!shouldBypass) {
    const cached = apiCache.get<T>(key);
    if (cached !== null && !apiCache.isStale(key)) {
      return cached;
    }
  }

  const data = await withRetry(() =>
    apiClient.get<T>(url, { 
      signal: options?.signal, 
      params: options?.params, 
      timeout: options?.timeout,
      schema: options?.schema,
      // Pass custom TTL to interceptor
      ...(options?.ttl ? { metadata: { ttl: options.ttl } } : {})
    } as AxiosRequestConfig).then((res) => res.data)
  );

  return data;
}

export async function cachedPost<T>(url: string, body?: unknown, options?: CachedRequestOptions): Promise<T> {
  const res = await withRetry(() =>
    apiClient.post<T>(url, body, { 
      signal: options?.signal, 
      params: options?.params, 
      timeout: options?.timeout,
      schema: options?.schema
    } as AxiosRequestConfig).then((res) => res.data)
  );
  return res;
}
