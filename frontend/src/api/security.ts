import { apiClient, cachedGet } from './core';

export interface RateLimitBucket {
  endpoint: string;
  requests_per_second: number;
  recent_count: number;
  limit_per_second: number | null;
}

export interface RateLimitStatus {
  enabled: boolean;
  buckets: RateLimitBucket[];
}

export interface SecurityEvent {
  id: number;
  timestamp: string;
  event_type: string;
  status_code: number | null;
  method: string | null;
  path: string | null;
  client_ip: string | null;
  api_key_id: string | null;
  detail: string;
}

export interface ApiKeyRecord {
  id: string;
  masked_key: string;
  role: 'read_only' | 'worker' | 'admin';
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  active: boolean;
}

export interface GeneratedApiKey extends ApiKeyRecord {
  api_key: string;
}

export interface CspReport {
  id: number;
  timestamp: string;
  client_ip: string | null;
  user_agent: string;
  report: Record<string, unknown>;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
  role: 'read_only' | 'worker' | 'admin';
}

export async function getRateLimitStatus(): Promise<RateLimitStatus> {
  return cachedGet<RateLimitStatus>('/api/security/rate-limit-status', { bypassCache: true });
}

export async function getSecurityEvents(): Promise<SecurityEvent[]> {
  return cachedGet<SecurityEvent[]>('/api/security/events', { bypassCache: true });
}

export async function getApiKeys(): Promise<ApiKeyRecord[]> {
  return cachedGet<ApiKeyRecord[]>('/api/security/api-keys', { bypassCache: true });
}

   
export async function generateApiKey(role: ApiKeyRecord['role']): Promise<GeneratedApiKey> {
  const response = await apiClient.post<GeneratedApiKey>('/api/security/api-keys', { role });
  return response.data;
}

export async function revokeApiKey(id: string): Promise<void> {
  await apiClient.delete(`/api/security/api-keys/${encodeURIComponent(id)}`);
}

export async function getCspReports(): Promise<CspReport[]> {
  return cachedGet<CspReport[]>('/api/security/csp-reports', { bypassCache: true });
}

export async function createToken(apiKey: string): Promise<TokenResponse> {
  const response = await apiClient.post<TokenResponse>('/api/auth/token', { api_key: apiKey });
  return response.data;
}

/**
 * Verify the current auth token is still valid by hitting a lightweight
 * authenticated endpoint. Returns the server response if valid, or null
 * if the token is expired/revoked (401).
 */
export async function verifyAuthToken(signal?: AbortSignal): Promise<{ valid: boolean; user?: Record<string, unknown> }> {
  try {
    const { data } = await apiClient.get<{ user?: Record<string, unknown> }>('/api/auth/me', { signal, timeout: 5000 });
    return { valid: true, user: data?.user };
  } catch (err: unknown) {
    const status = (err as { status?: number })?.status;
    if (status === 401 || status === 403) {
      return { valid: false };
    }
    // Network error or other issue — treat as "can't verify" rather than "invalid"
    return { valid: true };
  }
}

export async function createGuestToken(baseUrl?: string): Promise<{ ok: boolean; data?: TokenResponse; error?: Error }> {
  try {
    const { default: axios } = await import('axios');
    const client = baseUrl
      ? axios.create({ ...apiClient.defaults, baseURL: baseUrl })
      : apiClient;
    const response = await client.post<TokenResponse>('/api/auth/token', { mode: 'guest' });
    return { ok: true, data: response.data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err : new Error(String(err)) };
  }
}

export interface CsrfTokenResponse {
  csrf_token: string;
}

export async function getCsrfToken(signal?: AbortSignal): Promise<CsrfTokenResponse> {
  const { data } = await apiClient.get<CsrfTokenResponse>('/api/csrf-token', {
    signal,
    withCredentials: true,
  });
  return data;
}

export interface CspReportPayload {
  'csp-report': Record<string, unknown>;
}

export async function submitCspReport(report: Record<string, unknown>, signal?: AbortSignal): Promise<{ status: string }> {
  const { data } = await apiClient.post<{ status: string }>('/api/csp-report', { 'csp-report': report }, { signal });
  return data;
}
