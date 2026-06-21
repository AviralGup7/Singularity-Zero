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

export async function getProjects(signal?: AbortSignal): Promise<Project[]> {
  const res = await cachedGet<Project[]>('/api/projects', { signal, ttl: 60000 });
  return res ?? [];
}

export async function getProject(projectId: string, signal?: AbortSignal): Promise<ProjectDetail> {
  return cachedGet<ProjectDetail>(`/api/projects/${projectId}`, { signal, ttl: 60000 });
}
