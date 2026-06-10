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

export async function globalSearch(
  params: GlobalSearchParams,
  signal?: AbortSignal
): Promise<GlobalSearchResponse> {
  try {
    const { data } = await apiClient.get<GlobalSearchResponse>('/api/search', {
      params: { q: params.q, limit: params.limit ?? 20 },
      signal,
    });
    return data;
  } catch {
    // Fallback to empty results if backend search is not available
    return { results: [], total: 0 };
  }
}
