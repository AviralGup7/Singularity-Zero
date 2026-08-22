import { useState, useCallback } from 'react';

interface SavedFilterPreset {
  id: string;
  name: string;
  filters: Record<string, string>;
  createdAt: string;
}

const STORAGE_KEY = 'cyber-pipeline-saved-filters';

export function parseSavedFilterPresets(raw: string | null): SavedFilterPreset[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is SavedFilterPreset => {
      return Boolean(item && typeof item === 'object' && typeof (item as SavedFilterPreset).id === 'string');
    });
  } catch {
    return [];
  }
}

export function normalizePresetName(name: string): string | null {
  const trimmed = name.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function getSavedFilterPresets(): SavedFilterPreset[] {
  try {
    return parseSavedFilterPresets(localStorage.getItem(STORAGE_KEY));
  } catch {
    return [];
  }
}

export function saveFilterPreset(name: string, filters: Record<string, string>): SavedFilterPreset {
  const label = normalizePresetName(name) ?? 'Untitled filter';
  const preset: SavedFilterPreset = {
    id: `preset-${crypto.randomUUID()}`,
    name: label,
    filters,
    createdAt: new Date().toISOString(),
  };
  const presets = getSavedFilterPresets();
  presets.push(preset);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(presets));
  return preset;
}

export function loadFilterPreset(id: string): SavedFilterPreset | null {
  const presets = getSavedFilterPresets();
  return presets.find((p) => p.id === id) || null;
}

export function deleteFilterPreset(id: string): void {
  const presets = getSavedFilterPresets();
  const filtered = presets.filter((p) => p.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
}

export function useSavedFilterPresets() {
   
  const [presets, setPresets] = useState<SavedFilterPreset[]>(getSavedFilterPresets);

  const save = useCallback((name: string, filters: Record<string, string>) => {
    const preset = saveFilterPreset(name, filters);
    setPresets(getSavedFilterPresets());
    return preset;
  }, []);

  const load = useCallback((id: string): SavedFilterPreset | null => {
    return loadFilterPreset(id);
  }, []);

  const remove = useCallback((id: string) => {
    deleteFilterPreset(id);
    setPresets(getSavedFilterPresets());
  }, []);

  return { presets, save, load, remove };
}
