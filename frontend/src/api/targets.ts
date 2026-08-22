import type { Target, Defaults, Finding } from '@/types/api';
import { apiClient, cachedGet } from './core';
import { apiCache } from './cache';
import { asNumber, asRecord, asString, normalizeFindingRecord } from './contract';

export function normalizeTargetRecord(raw: unknown): Target | null {
  const rec = asRecord(raw);
  if (!rec) return null;
  const name = asString(rec.name);
  if (!name) return null;
  return {
    ...(rec as unknown as Target),
    name,
    href: asString(rec.href || `/targets/${encodeURIComponent(name)}`),
    latest_run: asString(rec.latest_run),
    latest_generated_at: asString(rec.latest_generated_at),
    latest_report_href: asString(rec.latest_report_href),
    priority_url_count: asNumber(rec.priority_url_count),
    finding_count: asNumber(rec.finding_count),
    validated_leads: asNumber(rec.validated_leads),
    url_count: asNumber(rec.url_count),
    parameter_count: asNumber(rec.parameter_count),
    new_findings: asNumber(rec.new_findings),
    attack_chain_count: asNumber(rec.attack_chain_count),
    max_attack_chain_confidence: asNumber(rec.max_attack_chain_confidence),
    validation_plan_count: asNumber(rec.validation_plan_count),
    top_finding_title: asString(rec.top_finding_title),
    top_finding_severity: asString(rec.top_finding_severity),
    top_finding_url: asString(rec.top_finding_url),
    severity_counts: (asRecord(rec.severity_counts) as Record<string, number>) ?? {},
    run_count: asNumber(rec.run_count),
    last_scan: rec.last_scan != null ? asString(rec.last_scan) : undefined,
    risk_score: rec.risk_score != null ? asNumber(rec.risk_score) : undefined,
  };
}

export function asTargetList(value: unknown): Target[] {
  const rec = asRecord(value);
  const source = Array.isArray(value) ? value : rec && Array.isArray(rec.targets) ? rec.targets : [];
  return source.map((item) => normalizeTargetRecord(item)).filter((item): item is Target => Boolean(item));
}

export function asTargetFindings(value: unknown): Finding[] {
  const rec = asRecord(value);
  const source = Array.isArray(value) ? value : rec && Array.isArray(rec.findings) ? rec.findings : [];
  return source
    .map((item) => normalizeFindingRecord(item) as Finding | null)
    .filter((item): item is Finding => Boolean(item?.id));
}

export async function getTargets(signal?: AbortSignal, ttl?: number): Promise<{ targets: Target[] }> {
  const res = await cachedGet<{ targets: Target[] }>('/api/targets', { signal, ttl });
  return { ...res, targets: asTargetList(res.targets) };
}

export async function getDefaults(signal?: AbortSignal, ttl?: number): Promise<Defaults> {
  return cachedGet<Defaults>('/api/defaults', { signal, ttl });
}

export async function deleteTarget(id: string, signal?: AbortSignal): Promise<void> {
  await apiClient.delete(`/api/targets/${encodeURIComponent(id)}`, { signal });
  apiCache.invalidatePrefix('/api/targets');
}

export async function compareTargets(
  targetA: string,
  targetB: string,
  signal?: AbortSignal
): Promise<{ target_a: Target; target_b: Target }> {
  if (!String(targetA ?? '').trim() || !String(targetB ?? '').trim()) {
    throw new Error('Both targets are required');
  }
  const { data } = await apiClient.get<{ target_a: Target; target_b: Target }>('/api/targets/compare', {
    params: { target_a: targetA, target_b: targetB },
    signal,
  });
  return data;
}

export async function getTargetFindings(
  targetName: string,
  run?: string,
  signal?: AbortSignal,
): Promise<{ target: string; findings: import('@/types/api').Finding[]; total: number }> {
  const { data } = await apiClient.get<{ target: string; findings: import('@/types/api').Finding[]; total: number }>(
    `/api/targets/${encodeURIComponent(targetName)}/findings`,
    { params: run ? { run } : undefined, signal },
  );
  const findings = asTargetFindings(data);
  return { ...data, findings, total: Number.isFinite(data.total) ? data.total : findings.length };
}

