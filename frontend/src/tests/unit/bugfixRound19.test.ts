import { describe, expect, it } from 'vitest';
import { isNoTelemetryState } from '@/components/gap-analysis/gapTelemetry';

describe('gap telemetry empty state', () => {
  it('does not treat a zero-module payload as missing telemetry', () => {
    expect(isNoTelemetryState({
      results: [{ module: 'x' }],
      overall_coverage: 0,
      modules_with_gaps: 0,
      total_modules: 0,
    })).toBe(false);
    expect(isNoTelemetryState({
      results: [{ module: 'x' }],
      overall_coverage: 0,
      modules_with_gaps: 4,
      total_modules: 4,
    })).toBe(true);
  });
});
