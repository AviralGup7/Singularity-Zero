// ============================================================
// Additional TypeScript types for backend schemas not yet covered
// ============================================================

export interface RiskScore {
  target: string;
  aggregate_score: number;
  severity: string;
  total_findings: number;
  severity_breakdown: Record<string, number>;
  timestamp: string;
}

export interface HistoricalScoreEntry {
  score: number;
  severity: string;
  timestamp: string;
  findings: Record<string, unknown>[];
}

export interface HistoricalScoreResponse {
  target: string;
  endpoints: Record<string, Record<string, unknown>>;
  runs_analyzed: number;
}

export interface TimelineEntry {
  timestamp: string;
  severity: string;
  url: string;
  title: string;
  module: string;
}

export interface TimelineResponse {
  target: string;
  timeline: TimelineEntry[];
  count: number;
}
export interface Note {
  id: string;
  finding_id: string;
  note: string;
  tags: string[];
  author: string;
  created_at: string;
  updated_at: string;
  graph_node_id?: string;
  graph_edge_id?: string;
  exchange_id?: string;
}

export interface NoteListResponse {
  notes: Note[];
  target: string;
  count: number;
}

export interface NoteCreateRequest {
  finding_id: string;
  note: string;
  tags?: string[];
  author?: string;
  graph_node_id?: string;
  graph_edge_id?: string;
  exchange_id?: string;
}

export interface NoteUpdateRequest {
  note?: string;
  tags?: string[];
}

export interface NoteDeleteResponse {
  deleted: boolean;
  note_id: string;
}

export interface CacheStats {
  total_entries: number;
  active_entries: number;
  expired_entries: number;
  total_size_bytes: number;
  namespaces: Record<string, number>;
  metrics: Record<string, unknown>;
  backend_type: string;
  l1_entries: number;
  l2_entries: number;
  l3_entries: number;
}

export interface CacheCleanupResponse {
  cleaned: number;
  duration_seconds: number;
}

export interface CacheNamespaceResponse {
  cleared: number;
  namespace: string;
}

export interface RedisCacheOverview {
  connected: boolean;
  keys_count: number;
  used_memory_human: string;
  used_memory_bytes: number;
  max_memory_bytes?: number | null;
  hit_rate?: number | null;
  miss_rate?: number | null;
  connected_clients: number;
  error?: string | null;
}

export interface SQLiteCacheOverview {
  connected: boolean;
  db_path: string;
  file_size_mb: number;
  query_count: number;
  entry_count: number;
  cache_hit_ratio?: number | null;
  error?: string | null;
}

export interface CacheStatusResponse {
  redis: RedisCacheOverview;
  sqlite: SQLiteCacheOverview;
}

export interface CacheKeyInfo {
  key: string;
  ttl?: number | null;
  size?: number | null;
  type?: string | null;
}

export interface CacheKeysResponse {
  pattern: string;
  limit: number;
  count: number;
  truncated: boolean;
  connected: boolean;
  keys: CacheKeyInfo[];
  error?: string | null;
}

export interface CacheKeyDeleteResponse {
  pattern: string;
  matched: number;
  deleted: number;
  connected: boolean;
  error?: string | null;
}

export interface CachePerformancePoint {
  timestamp: string;
  epoch: number;
  hit_rate?: number | null;
  miss_rate?: number | null;
  redis_hit_rate?: number | null;
  redis_miss_rate?: number | null;
  local_hit_rate?: number | null;
  local_miss_rate?: number | null;
}

export interface CachePerformanceHistoryResponse {
  points: CachePerformancePoint[];
}

export interface ReadinessResponse {
  ready: boolean;
  checks: Record<string, boolean>;
}

export interface JobTimelineEntry {
  timestamp: string;
  stage: string;
  stage_label: string;
  event: string;
  details?: Record<string, unknown>;
}

export interface JobTimelineResponse {
  job_id: string;
  timeline: JobTimelineEntry[];
  count: number;
}

export interface TargetRiskScore {
  target: string;
  aggregate_score: number;
  severity: string;
  total_findings: number;
  severity_breakdown: Record<string, number>;
  timestamp: string;
}

export interface RiskHistoryEntry {
  target_id: string;
  target: string;
  csi_value: number;
  timestamp: string;
  severity_breakdown: Record<string, number>;
  factors: Record<'cvss' | 'confidence' | 'exploitability' | 'mesh_consensus', number>;
  top_findings: Array<{
    id: string;
    title: string;
    severity: string;
    url: string;
  }>;
}

export interface RiskFactorDefinition {
  key: 'cvss' | 'confidence' | 'exploitability' | 'mesh_consensus';
  label: string;
  description: string;
}

export interface RiskFactorsResponse {
  weights: Record<RiskFactorDefinition['key'], number>;
  factors: RiskFactorDefinition[];
}

export interface FindingTimelineEvent {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target: string;
  timestamp: string;
  finding_id: string;
  job_id?: string;
  url?: string;
  module?: string;
  preview?: string;
  confidence?: number;
}

export interface TargetHistoricalScores {
  target: string;
  endpoints: Record<string, {
    scores: number[];
    timestamps: string[];
    avg_score: number;
    trend: 'improving' | 'worsening' | 'stable';
  }>;
  runs_analyzed: number;
}
