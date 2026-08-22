export function deepMergeSettings<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
  const result = { ...target } as Record<string, unknown>;
  for (const key of Object.keys(source)) {
    const sourceVal = source[key as keyof T];
    const targetVal = target[key as keyof T];
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (sourceVal === undefined) continue;
    if (
      sourceVal !== null &&
      typeof sourceVal === 'object' &&
      !Array.isArray(sourceVal) &&
      targetVal !== null &&
      typeof targetVal === 'object' &&
      !Array.isArray(targetVal)
    ) {
      result[key] = deepMergeSettings(
        targetVal as Record<string, unknown>,
        sourceVal as Record<string, unknown>,
      );
    } else {
      result[key] = sourceVal;
    }
  }
  return result as T;
}

export function pickPreferredFilter(urlValue: string | null, storedValue: string): string {
  if (urlValue === null) return storedValue;
  return urlValue;
}
