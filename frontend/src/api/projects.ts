import { cachedGet } from './core';

export interface Project {
  id: string;
  config_file: string;
  name: string;
  description: string;
  scope: string;
  rewards: string;
  program_url: string;
  exclusions: string[];
  rate_limits: Record<string, number>;
}

export interface ProjectDetail extends Project {
  config: Record<string, unknown>;
  scope_text: string;
}

export function asProjectList(value: unknown): Project[] {
  return Array.isArray(value) ? value as Project[] : [];
}

export async function getProjects(signal?: AbortSignal): Promise<Project[]> {
  const res = await cachedGet<Project[] | { projects?: Project[] }>('/api/projects', { signal, ttl: 60000 });
  if (Array.isArray(res)) return res;
  return asProjectList((res as { projects?: Project[] })?.projects);
}

export async function getProject(projectId: string, signal?: AbortSignal): Promise<ProjectDetail> {
  const id = String(projectId ?? '').trim();
  if (!id) throw new Error('Project id is required');
  return cachedGet<ProjectDetail>(`/api/projects/${encodeURIComponent(id)}`, { signal, ttl: 60000 });
}
