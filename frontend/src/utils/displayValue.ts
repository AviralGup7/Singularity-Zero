export function displayNumericOrNA(value: number | string | null | undefined): string {
  if (value === null || value === undefined) return 'N/A';
  if (typeof value === 'string' && value.trim() === '') return 'N/A';
  if (typeof value === 'number' && !Number.isFinite(value)) return 'N/A';
  return String(value);
}
