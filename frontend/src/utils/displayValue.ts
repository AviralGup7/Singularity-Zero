export function displayNumericOrNA(value: number | string | null | undefined): string {
  if (value === null || value === undefined || value === '') return 'N/A';
  if (typeof value === 'number' && !Number.isFinite(value)) return 'N/A';
  return String(value);
}
