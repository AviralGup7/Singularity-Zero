import { useState, useCallback } from 'react';
import { Bookmark, BookmarkCheck, Trash2, ChevronDown } from 'lucide-react';
import { useSavedFilterPresets } from '@/hooks/useSavedFilterPresets';

interface SavedFilterPresetsProps {
  currentFilters: Record<string, string>;
  onLoadPreset: (filters: Record<string, string>) => void;
  className?: string;
}

export function SavedFilterPresets({ currentFilters, onLoadPreset, className }: SavedFilterPresetsProps) {
  const { presets, save, load, remove } = useSavedFilterPresets();
  const [isOpen, setIsOpen] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [presetName, setPresetName] = useState('');

  const handleSave = useCallback(() => {
    if (!presetName.trim()) return;
    save(presetName.trim(), currentFilters);
    setPresetName('');
    setIsSaving(false);
  }, [presetName, currentFilters, save]);

  const handleLoad = useCallback((id: string) => {
    const preset = load(id);
    if (preset) {
      onLoadPreset(preset.filters);
    }
    setIsOpen(false);
  }, [load, onLoadPreset]);

  const handleDelete = useCallback((id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    remove(id);
  }, [remove]);

  const hasActiveFilters = Object.values(currentFilters).some(v => v && v !== 'all' && v !== '');

  return (
    <div className={`relative ${className}`}>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="btn btn-sm btn-secondary flex items-center gap-1.5"
          aria-expanded={isOpen}
          aria-haspopup="listbox"
        >
          <Bookmark size={14} />
          <span>Saved Filters</span>
          <ChevronDown size={12} className={`transition-transform ${isOpen ? 'rotate-180' : ''}`} />
        </button>

        {hasActiveFilters && (
          <button
            type="button"
            onClick={() => setIsSaving(true)}
            className="btn btn-sm btn-ghost flex items-center gap-1.5"
            title="Save current filters as a preset"
          >
            <BookmarkCheck size={14} />
            <span>Save Current</span>
          </button>
        )}
      </div>

      {isSaving && (
        <div className="absolute top-full left-0 mt-2 z-50 bg-panel border border-white/10 rounded-xl shadow-2xl p-4 min-w-[280px]">
          <h4 className="text-xs font-bold uppercase tracking-wider text-muted mb-3">Save Filter Preset</h4>
          <div className="flex gap-2">
              <input
                type="text"
                value={presetName}
                onChange={(e) => setPresetName(e.target.value)}
                placeholder="Preset name..."
                className="flex-1 bg-black/40 border border-white/10 rounded-lg px-3 py-1.5 text-xs font-mono text-text focus:border-accent/50 outline-none"
                onKeyDown={(e) => e.key === 'Enter' && handleSave()}
              />
            <button
              type="button"
              onClick={handleSave}
              disabled={!presetName.trim()}
              className="btn btn-sm btn-primary disabled:opacity-40"
            >
              Save
            </button>
            <button
              type="button"
              onClick={() => { setIsSaving(false); setPresetName(''); }}
              className="btn btn-sm btn-ghost"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

          {isOpen && (
        <div className="absolute top-full left-0 mt-2 z-50 bg-panel border border-white/10 rounded-xl shadow-2xl min-w-[280px] max-h-[300px] overflow-y-auto">
          {presets.length === 0 ? (
            <div className="p-4 text-center text-muted text-xs">
              <Bookmark size={24} className="mx-auto mb-2 opacity-40" />
              <p>No saved filter presets yet.</p>
              <p className="mt-1 text-[10px]">Apply filters and click "Save Current" to create one.</p>
            </div>
          ) : (
            <ul role="listbox" className="py-1" aria-label="Saved filter presets">
              {presets.map((preset) => (
                <li
                  key={preset.id}
                  role="option"
                  aria-selected={false}
                  tabIndex={0}
                  className="flex items-center justify-between px-3 py-2 hover:bg-white/5 cursor-pointer group"
                  onClick={() => handleLoad(preset.id)}
                  onKeyDown={(e) => e.key === 'Enter' && handleLoad(preset.id)}
                >
                  <div className="flex items-center gap-2">
                    <Bookmark size={12} className="text-accent" />
                    <div>
                      <div className="text-xs font-bold text-text">{preset.name}</div>
                      <div className="text-[10px] text-muted">
                        {Object.entries(preset.filters)
                          .filter(([, v]) => v)
                          .map(([k, v]) => `${k}: ${v}`)
                          .join(', ') || 'No filters'}
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => handleDelete(preset.id, e)}
                    className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-bad/20 text-muted hover:text-bad transition-all"
                    aria-label={`Delete preset: ${preset.name}`}
                  >
                    <Trash2 size={12} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
