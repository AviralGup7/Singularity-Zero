export function parsePersistedValue<T>(raw: string | null, defaultValue: T, deserialize: (text: string) => T = JSON.parse): T {
  if (raw === null) return defaultValue;
  try {
    return deserialize(raw);
  } catch {
    if (typeof defaultValue === 'string') return raw as T;
    return defaultValue;
  }
}
