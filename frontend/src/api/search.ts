import { apiClient } from './core';

export interface GlobalSearchParams {
  q: string;
  limit?: number;
}

export interface GlobalSearchResult {
  id: string;
  type: 'target' | 'job' | 'finding' | 'page';
  title: string;
  subtitle?: string;
  href?: string;
  meta?: string;
}

export interface GlobalSearchResponse {
  results: GlobalSearchResult[];
  total: number;
}

export function asSearchResults(value: unknown): GlobalSearchResult[] {
  return Array.isArray(value) ? value as GlobalSearchResult[] : [];
}

export function sanitizeSearchQuery(q: string): string {
  return String(q ?? '').trim();
}

export async function globalSearch(
  params: GlobalSearchParams,
  signal?: AbortSignal
): Promise<GlobalSearchResponse> {
  const q = sanitizeSearchQuery(params.q);
  if (!q) return { results: [], total: 0 };
  try {
    const { data } = await apiClient.get<GlobalSearchResponse>('/api/search', {
      params: { q, limit: params.limit ?? 20 },
      signal,
    });
    const results = asSearchResults(data.results);
    return { ...data, results, total: Number.isFinite(data.total) ? data.total : results.length };
  } catch {
    return { results: [], total: 0 };
  }
}
