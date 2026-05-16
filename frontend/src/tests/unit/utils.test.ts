import { describe, it, expect } from 'vitest';
import {
  classifyLogLine,
  getStageIcon,
  calculateHealthScore,
  getPageNumbers,
  getStatusColor,
  getStatusLabel,
  formatBytes,
} from '@/lib/utils';

describe('classifyLogLine', () => {
  it('classifies error lines', () => {
    expect(classifyLogLine('ERROR: connection failed')).toBe('log-line log-error');
    expect(classifyLogLine('Exception in thread')).toBe('log-line log-error');
    expect(classifyLogLine('FATAL: shutdown')).toBe('log-line log-error');
    expect(classifyLogLine('Traceback (most recent call)')).toBe('log-line log-error');
  });

  it('classifies warning lines', () => {
    expect(classifyLogLine('WARN: deprecated API')).toBe('log-line log-warn');
    expect(classifyLogLine('Warning: low memory')).toBe('log-line log-warn');
  });

  it('classifies success lines', () => {
    expect(classifyLogLine('SUCCESS: scan complete')).toBe('log-line log-success');
    expect(classifyLogLine('Task complete')).toBe('log-line log-success');
    expect(classifyLogLine('All done')).toBe('log-line log-success');
  });

  it('classifies info lines', () => {
    expect(classifyLogLine('INFO: starting scan')).toBe('log-line log-info');
    expect(classifyLogLine('Starting module')).toBe('log-line log-info');
    expect(classifyLogLine('Loading config')).toBe('log-line log-info');
  });

  it('returns default for unclassified lines', () => {
    expect(classifyLogLine('just a regular line')).toBe('log-line');
    expect(classifyLogLine('')).toBe('log-line');
  });

  it('is case insensitive', () => {
    expect(classifyLogLine('error: something')).toBe('log-line log-error');
    expect(classifyLogLine('Error: something')).toBe('log-line log-error');
    expect(classifyLogLine('ERROR: something')).toBe('log-line log-error');
  });
});

describe('getStageIcon', () => {
  it('returns correct icons for known stages', () => {
    expect(getStageIcon('discovery')).toBe('🔍');
    expect(getStageIcon('collection')).toBe('🕸️');
    expect(getStageIcon('analysis')).toBe('🧠');
    expect(getStageIcon('validation')).toBe('✅');
    expect(getStageIcon('reporting')).toBe('📊');
    expect(getStageIcon('complete')).toBe('🏁');
    expect(getStageIcon('failed')).toBe('❌');
    expect(getStageIcon('stopped')).toBe('⏹️');
  });

  it('returns default icon for unknown stages', () => {
    expect(getStageIcon('unknown')).toBe('⚙️');
    expect(getStageIcon('')).toBe('⚙️');
  });

  it('is case insensitive', () => {
    expect(getStageIcon('DISCOVERY')).toBe('🔍');
    expect(getStageIcon('Analysis')).toBe('🧠');
  });

  it('matches partial stage labels', () => {
    expect(getStageIcon('Discovery Phase 1')).toBe('🔍');
    expect(getStageIcon('Data Collection')).toBe('🕸️');
  });
});

describe('calculateHealthScore', () => {
  it('returns Healthy for no findings', () => {
    const result = calculateHealthScore({});
    expect(result.score).toBe(100);
    expect(result.label).toBe('Healthy');
    expect(result.tone).toBe('info');
  });

  it('calculates score correctly', () => {
    const result = calculateHealthScore({ critical: 2, high: 1, medium: 3 });
    expect(result.score).toBe(Math.max(0, 100 - Math.min(100, 2 * 15 + 1 * 8 + 3 * 3)));
    expect(result.score).toBe(53);
    expect(result.label).toBe('Moderate Risk');
    expect(result.tone).toBe('ok');
  });

  it('bottoms out score at 0 for very high findings', () => {
    const result = calculateHealthScore({ critical: 10, high: 10, medium: 10 });
    expect(result.score).toBe(0);
    expect(result.label).toBe('Critical');
    expect(result.tone).toBe('bad');
  });

  it('caps score at 100 for clean runs', () => {
    const result = calculateHealthScore({});
    expect(result.score).toBe(100);
    expect(result.label).toBe('Healthy');
    expect(result.tone).toBe('info');
  });

  it('handles missing severity keys', () => {
    const result = calculateHealthScore({ critical: 1 });
    expect(result.score).toBe(85);
    expect(result.label).toBe('Healthy');
    expect(result.tone).toBe('info');
  });

  it('classifies all health labels correctly', () => {
    expect(calculateHealthScore({ critical: 7 }).label).toBe('Critical');
    expect(calculateHealthScore({ critical: 5 }).label).toBe('At Risk');
    expect(calculateHealthScore({ high: 7 }).label).toBe('High Risk');
    expect(calculateHealthScore({ medium: 12 }).label).toBe('Moderate Risk');
    expect(calculateHealthScore({ medium: 4 }).label).toBe('Healthy');
    expect(calculateHealthScore({}).label).toBe('Healthy');
  });
});

describe('getPageNumbers', () => {
  it('returns all pages when total is small', () => {
   
    expect(getPageNumbers(1, 5)).toEqual([1, 2, 3, 4, 5]);
  });

  it('shows ellipsis for large page counts', () => {
    const result = getPageNumbers(10, 20);
    expect(result).toContain(1);
    expect(result).toContain('...');
    expect(result).toContain(20);
    expect(result).toContain(9);
    expect(result).toContain(10);
    expect(result).toContain(11);
  });

  it('handles first page', () => {
    const result = getPageNumbers(1, 10);
   
    expect(result[0]).toBe(1);
    expect(result).toContain('...');
   
    expect(result[result.length - 1]).toBe(10);
  });

  it('handles last page', () => {
    const result = getPageNumbers(10, 10);
   
    expect(result[0]).toBe(1);
    expect(result).toContain('...');
   
    expect(result[result.length - 1]).toBe(10);
  });

  it('returns single page', () => {
   
    expect(getPageNumbers(1, 1)).toEqual([1]);
  });
});

describe('getStatusColor', () => {
  it('returns muted for null', () => {
    expect(getStatusColor(null)).toBe('var(--muted)');
  });

  it('returns bad for true', () => {
    expect(getStatusColor(true)).toBe('var(--bad)');
  });

  it('returns ok for false', () => {
    expect(getStatusColor(false)).toBe('var(--ok)');
  });
});

describe('getStatusLabel', () => {
  it('returns Unknown for null', () => {
    expect(getStatusLabel(null)).toBe('Unknown');
  });

  it('returns Changed for true', () => {
    expect(getStatusLabel(true)).toBe('Changed');
  });

  it('returns Unchanged for false', () => {
    expect(getStatusLabel(false)).toBe('Unchanged');
  });
});

describe('formatBytes', () => {
  it('formats zero bytes', () => {
    expect(formatBytes(0)).toBe('0 B');
  });

  it('formats bytes', () => {
    expect(formatBytes(500)).toBe('500 B');
  });

  it('formats kilobytes', () => {
    expect(formatBytes(1024)).toBe('1 KB');
    expect(formatBytes(1536)).toBe('1.5 KB');
  });

  it('formats megabytes', () => {
    expect(formatBytes(1048576)).toBe('1 MB');
  });

  it('formats gigabytes', () => {
    expect(formatBytes(1073741824)).toBe('1 GB');
  });
});
