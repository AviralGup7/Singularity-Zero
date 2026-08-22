import { describe, expect, it } from 'vitest';
import { estimateStagePercent, normalizeStageEntry, synthesizeCurrentStageEntry } from '@/hooks/useJobMonitorUtils';
import { clampScanProgress } from '@/hooks/useScanProgress';
import { parseEvidenceRecords } from '@/utils/evidenceChain';

describe('stage percent', () => {
  it('does not paint NaN for a non-finite poll value', () => {
    expect(estimateStagePercent('urls', Number.NaN)).toBe(0);
    expect(estimateStagePercent('urls', 50)).toBeGreaterThanOrEqual(0);
  });
});

describe('synthesized stage', () => {
  it('clamps a NaN stage percent to 0', () => {
    const entry = synthesizeCurrentStageEntry({ stage: 'urls', stage_percent: Number.NaN, status: 'running' });
    expect(entry?.percent).toBe(0);
  });
});

describe('stage entry numbers', () => {
  it('treats non-finite processed/percent as zero', () => {
    const entry = normalizeStageEntry({ stage: 'urls', processed: Number.NaN, percent: Number.NaN });
    expect(entry.processed).toBe(0);
    expect(entry.percent).toBe(0);
  });
});

describe('scan progress clamp', () => {
  it('caps overflow and drops NaN', () => {
    expect(clampScanProgress(140)).toBe(100);
    expect(clampScanProgress(Number.NaN)).toBe(0);
  });
});

describe('evidence store', () => {
  it('ignores a non-array blob', () => {
    expect(parseEvidenceRecords('{"id":"x"}')).toEqual([]);
    expect(parseEvidenceRecords('[{"id":"e1"}]')).toHaveLength(1);
  });
});
