import type {
  
  
  DashboardStats,
} from '@/types/api';
import { apiClient, cachedGet } from './core';

export { apiClient, cachedGet } from './core';

export { getOnlineStatus } from './networkStatus';

export async function getDashboardStats(signal?: AbortSignal, ttl?: number): Promise<DashboardStats> {
  return cachedGet<DashboardStats>('/api/dashboard', { signal, ttl });
}

export { getTargets, getDefaults, deleteTarget } from './targets';
export { getJobs, getJob, getJobLogs, getJobTraceLink, getJobRemediation, startJob, stopJob, restartJob, getHistoricalDurations } from './jobs';
export type { StartJobPayload, HistoricalDurationEntry } from './jobs';
export { getFindingsSummary, getFindings, getFindingRemediation, deleteFinding, updateFinding, bulkUpdateFindings } from './findings';
export {
  getRegistry, getModuleRegistry, getAnalysisRegistry, getModeRegistry,
} from './registry';
export type {
  ModuleRegistryEntry, ModuleRegistryGroup, ModuleRegistryResponse,
  AnalysisCheckOption, AnalysisControlGroup, AnalysisFocusPreset,
  AnalysisRegistryResponse, ModePreset, ModeRegistryResponse,
} from './registry';
export { replayRequest } from './replay';
export type { ReplayParams } from './replay';
export { getHealth, getGapAnalysis, exportFindings, refreshGapAnalysis } from './reports';
export { getReadiness, getLiveness } from './health';
export { getNotes, createNote, updateNote, deleteNote } from './notes';
export type { Note, NoteListResponse, NoteCreateRequest, NoteUpdateRequest } from '@/types/extended';
export { getCacheStats, triggerCacheCleanup, invalidateCacheNamespace } from './cacheMgmt';
export type { CacheStats, CacheCleanupResponse } from '@/types/extended';
export { getTargetRiskScore, getTargetHistoricalScores, getTargetTimeline, getJobTimeline } from './analysis';
export type { RiskScore, HistoricalScoreResponse, TimelineResponse, TimelineEntry } from '@/types/extended';
export { exportTargetFindings, exportLatestFindings } from './export';
export {
  createToken,
  generateApiKey,
  getApiKeys,
  getCspReports,
  getRateLimitStatus,
  getSecurityEvents,
  revokeApiKey,
} from './security';
export type {
  ApiKeyRecord,
  CspReport,
  GeneratedApiKey,
  RateLimitStatus,
  SecurityEvent,
  TokenResponse,
} from './security';

export default apiClient;
