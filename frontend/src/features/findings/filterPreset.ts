import { sanitizeSeverityFilters } from './severityFilter';
import type { FindingSeverity } from './severityFilter';

export function applyFilterPreset(
  current: { search: string; severity: FindingSeverity[] },
  preset: Record<string, string>,
): { search: string; severity: FindingSeverity[] } {
  return {
    search: Object.prototype.hasOwnProperty.call(preset, 'search') ? String(preset.search ?? '') : current.search,
    severity: Object.prototype.hasOwnProperty.call(preset, 'severity')
      ? sanitizeSeverityFilters(String(preset.severity ?? '').split(','))
      : current.severity,
  };
}
