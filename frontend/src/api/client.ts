import type {
  DashboardStats,
} from '@/types/api';
import { apiClient, cachedGet } from './core';

export { apiClient, cachedGet } from './core';

export { getOnlineStatus } from './networkStatus';

export async function getDashboardStats(signal?: AbortSignal, ttl?: number): Promise<DashboardStats> {
  return cachedGet<DashboardStats>('/api/dashboard', { signal, ttl });
}

export { getTargets, getDefaults, deleteTarget, compareTargets, getTargetFindings } from './targets';
export {
  getJobs, getJob, getJobLogs, getJobTraceLink, getJobRemediation,
  startJob, stopJob, restartJob, pauseJob, resumeJob,
  getHistoricalDurations, jobProgressStreamUrl,
} from './jobs';
export type { StartJobPayload, HistoricalDurationEntry } from './jobs';
export {
  getFindingsSummary, getFindings, getFindingById, getFindingRemediation,
  deleteFinding, updateFinding, bulkUpdateFindings,
  getFindingsTimeline, getFindingExplain, getFindingAiExplain,
} from './findings';
export type { FindingsTimelineParams, FindingExplainResponse, FindingAiExplainResponse } from './findings';
export {
  getRegistry, getModuleRegistry, getAnalysisRegistry, getModeRegistry,
  getDynamicPluginCatalog, getCapabilities,
} from './registry';
export type {
  ModuleRegistryEntry, ModuleRegistryGroup, ModuleRegistryResponse,
  AnalysisCheckOption, AnalysisControlGroup, AnalysisFocusPreset,
  AnalysisRegistryResponse, DynamicPluginCatalogResponse, ModePreset, ModeRegistryResponse,
  CapabilitiesResponse,
} from './registry';
export { replayRequest } from './replay';
export type { ReplayParams } from './replay';
export {
  getHealth, getGapAnalysis, exportFindings, refreshGapAnalysis,
  getReportLibrary, getCompliancePdfUrl, getCompliancePdfHeaders,
  getAiExecutiveSummary, getSlaTrending,
} from './reports';
export type { ReportLibraryItem, ReportLibraryResponse, AiExecutiveSummary, SlaTrendingResponse } from './reports';
export { getReadiness, getLiveness } from './health';
export { getNotes, createNote, updateNote, deleteNote } from './notes';
export type { Note, NoteListResponse, NoteCreateRequest, NoteUpdateRequest } from '@/types/extended';
export { getCacheStats, triggerCacheCleanup, invalidateCacheNamespace, reconcileBloomFilter } from './cacheMgmt';
export { importSemgrepReport } from './imports';
export { getStreamToken, getStreamSubprotocols, appendStreamToken, AUTH_TOKEN_KEY } from './streamAuth';
export { pingLivenessForTimeSync, getMeshHealth, electMeshLeader, forceMeshReconcile } from './health';
export type { CacheStats, CacheCleanupResponse } from '@/types/extended';
export { getTargetRiskScore, getTargetHistoricalScores, getTargetTimeline, getJobTimeline } from './analysis';
export type { RiskScore, HistoricalScoreResponse, TimelineResponse, TimelineEntry } from '@/types/extended';
export {
  getThresholdHistory,
  getFPPatterns,
  getLearningKPIs,
  getLearningDbStats,
  getFeedbackEvents,
} from './learning';
export type {
  ThresholdHistoryEntry,
  FPPattern,
  LearningKPIs,
  FeedbackEventEntry,
} from './learning';
export { exportTargetFindings, exportLatestFindings } from './export';
export { listPlatformClients, pushFindingToPlatform } from './platforms';
export type { Platform, PlatformClientSummary, PlatformListResponse, SubmissionResult } from './platforms';
export {
  createToken, createGuestToken, generateApiKey, getApiKeys,
  getCspReports, getRateLimitStatus, getSecurityEvents, revokeApiKey,
  getCsrfToken, submitCspReport,
} from './security';
export type {
  ApiKeyRecord, CspReport, GeneratedApiKey, RateLimitStatus,
  SecurityEvent, TokenResponse, CsrfTokenResponse,
} from './security';
export {
  verifyTriageAudit, triggerAiReview,
} from './triage';
export type { AiReviewResponse } from './triage';
export { cockpitApi } from './cockpit';
export { verifyRemediation } from './remediated';
export type { RemediationVerification } from './remediated';
export {
  listAcceptances, createAcceptance, revokeAcceptance,
  listAssets, createAsset, deleteAsset,
  listControls, createControl,
  getSlaSummary,
  submitFindingReview, getFindingReviewHistory,
  getFindingLifecycle, transitionFinding,
} from './riskDomain';
export type {
  RiskAcceptance, AssetRecord, CompensatingControl,
  SlaSummaryEntry, FindingReview, FindingLifecycleEntry,
} from './riskDomain';
export { getRiskHistory, getRiskFactors } from './risk';
export { testWebhook, testSlackWebhook } from './webhooks';
export type { WebhookTestResult } from './webhooks';
export {
  getForensicsTrace, getForensicsTraceStage, getForensicsCausalChain,
} from './forensicsTrace';
export type { ForensicsTraceStage, ForensicsTrace, CausalChain } from './forensicsTrace';

export default apiClient;
