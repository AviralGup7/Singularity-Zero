export function isNoTelemetryState(data: {
  results: unknown[];
  overall_coverage: number;
  modules_with_gaps: number;
  total_modules: number;
} | null | undefined): boolean {
  if (!data || data.results.length === 0 || data.total_modules <= 0) return false;
  return data.overall_coverage === 0 && data.modules_with_gaps === data.total_modules;
}
