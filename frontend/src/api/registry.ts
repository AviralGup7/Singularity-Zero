export type { 
  RegistryData,
  AnalysisCheckOption,
  AnalysisControlGroup,
  AnalysisFocusPreset,
  ModePreset
} from '@/types/api';

import type { 
  RegistryData,
  AnalysisCheckOption,
  AnalysisControlGroup,
  AnalysisFocusPreset,
  ModePreset
} from '@/types/api';

import { cachedGet } from './core';

export interface ModuleRegistryEntry {
  name: string;
  label: string;
  description: string;
  kind: string;
  group: string;
  dependency_hint?: string;
  requires?: string[];
}

export interface ModuleRegistryGroup {
  name: string;
  label: string;
  description: string;
  icon: string;
}

export interface ModuleRegistryResponse {
  options: ModuleRegistryEntry[];
  groups: ModuleRegistryGroup[];
}

export interface AnalysisRegistryResponse {
  check_options: AnalysisCheckOption[];
  control_groups: AnalysisControlGroup[];
  focus_presets: AnalysisFocusPreset[];
}

export interface ModeRegistryResponse {
  presets: ModePreset[];
  stage_labels: Record<string, string>;
}

export async function getRegistry(signal?: AbortSignal, ttl?: number): Promise<RegistryData> {
  return cachedGet<RegistryData>('/api/registry', { signal, ttl });
}

export async function getModuleRegistry(signal?: AbortSignal, ttl?: number): Promise<ModuleRegistryResponse> {
  return cachedGet<ModuleRegistryResponse>('/api/registry/modules', { signal, ttl });
}

export async function getAnalysisRegistry(signal?: AbortSignal, ttl?: number): Promise<AnalysisRegistryResponse> {
  return cachedGet<AnalysisRegistryResponse>('/api/registry/analysis', { signal, ttl });
}

export async function getModeRegistry(signal?: AbortSignal, ttl?: number): Promise<ModeRegistryResponse> {
  return cachedGet<ModeRegistryResponse>('/api/registry/modes', { signal, ttl });
}
