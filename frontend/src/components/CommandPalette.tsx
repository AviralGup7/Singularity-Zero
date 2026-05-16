import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Icon } from './Icon';

export interface SearchableItem {
  id: string;
  type: 'target' | 'job' | 'finding' | 'page';
  title: string;
  subtitle?: string;
  href?: string;
  meta?: string;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  items: SearchableItem[];
}

const STORAGE_KEY = 'recent-searches';

function getRecentSearches(): string[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
}

function saveRecentSearch(query: string) {
  try {
    const recent = getRecentSearches();
   
    const updated = [query, ...recent.filter(r => r !== query)].slice(0, 10);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch {
    // ignore
  }
}

export function CommandPalette({ open, onClose, items }: CommandPaletteProps) {
   
  const [query, setQuery] = useState('');
   
  const [selectedIndex, setSelectedIndex] = useState(0);
   
  const [recentSearches, setRecentSearches] = useState<string[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!open) return;
    const tid = setTimeout(() => {
      setQuery('');
      setSelectedIndex(0);
      setRecentSearches(getRecentSearches());
    }, 0);
    return () => clearTimeout(tid);
   
  }, [open]);

  const filtered = useMemo(() => query.length > 0
    ? items.filter(item =>
        item.title.toLowerCase().includes(query.toLowerCase()) ||
        (item.subtitle && item.subtitle.toLowerCase().includes(query.toLowerCase())) ||
        (item.meta && item.meta.toLowerCase().includes(query.toLowerCase()))
      )
   
    : [], [items, query]);

  const grouped = useMemo(() => {
    const result = new Map<string, SearchableItem[]>();
    for (const item of filtered) {
      const existing = result.get(item.type);
      if (existing) {
        existing.push(item);
      } else {
   
        result.set(item.type, [item]);
      }
    }
    return result;
   
  }, [filtered]);

   
  const flatResults = useMemo(() => Array.from(grouped.values()).flat(), [grouped]);

  const typeLabels = new Map<string, string>([
   
    ['target', 'Targets'],
   
    ['job', 'Jobs'],
   
    ['finding', 'Findings'],
   
    ['page', 'Pages'],
  ]);

  const typeIcons = new Map<string, string>([
   
    ['target', 'target'],
   
    ['job', 'zap'],
   
    ['finding', 'shield'],
   
    ['page', 'file'],
  ]);

  useEffect(() => {
    if (open) {
      const tid = setTimeout(() => {
        inputRef.current?.focus();
      }, 50);
      return () => clearTimeout(tid);
    }
   
  }, [open]);

  const handleSelect = useCallback((item: SearchableItem) => {
    if (query.trim()) saveRecentSearch(query.trim());
    if (item.href) navigate(item.href);
    onClose();
   
  }, [navigate, onClose, query]);

  const clampedIndex = Math.min(selectedIndex, Math.max(0, flatResults.length - 1));

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => Math.min(prev + 1, flatResults.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => Math.max(prev - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const item = flatResults.at(clampedIndex);
      if (item) handleSelect(item);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
   
  }, [flatResults, clampedIndex, handleSelect, onClose]);

  useEffect(() => {
    if (listRef.current && selectedIndex >= 0) {
   
      const selected = listRef.current.querySelector('[data-selected="true"]');
      selected?.scrollIntoView({ block: 'nearest' });
    }
   
  }, [selectedIndex]);

  if (!open) return null;

  let globalIndex = 0;

  return (
    <div 
      className="command-palette-overlay" 
      onClick={onClose}
      onKeyDown={e => {
        if (e.key === 'Escape' || e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onClose();
        }
      }}
      role="button"
      tabIndex={0}
      aria-label="Close command palette"
    >
      <div 
        className="command-palette" 
        role="combobox" 
        aria-expanded={open} 
        aria-haspopup="listbox" 
        aria-controls="command-palette-listbox"
        onClick={e => e.stopPropagation()}
        onKeyDown={e => e.stopPropagation()}
        tabIndex={0}
      >
        <div className="command-palette-input">
          <Icon name="search" size={18} className="command-palette-icon" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Search targets, jobs, findings..."
            value={query}
            onChange={e => { setQuery(e.target.value); setSelectedIndex(0); }}
            onKeyDown={handleKeyDown}
            aria-label="Search"
            aria-autocomplete="list"
            aria-controls="command-palette-listbox"
            aria-activedescendant={flatResults.at(clampedIndex) ? `item-${flatResults.at(clampedIndex)?.id}` : undefined}
          />
          <kbd className="command-palette-kbd">ESC</kbd>
        </div>

        <div className="command-palette-body">
          {query.length === 0 && recentSearches.length > 0 && (
            <div className="command-palette-recent">
              <h4>Recent Searches</h4>
              <ul>
                {recentSearches.slice(0, 5).map(r => (
                  <li key={r}>
                    <button
                      onClick={() => setQuery(r)}
                      onKeyDown={e => e.key === 'Enter' && setQuery(r)}
                      className="command-palette-recent-btn"
                    >
                      <Icon name="clock" size={14} />
                      {r}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {query.length > 0 && flatResults.length === 0 && (
            <div className="command-palette-empty">
              <Icon name="search" size={24} />
              <p>No results for "{query}"</p>
            </div>
          )}

          {flatResults.length > 0 && (
            <ul 
              className="command-palette-results" 
              ref={listRef} 
              role="listbox" 
              id="command-palette-listbox"
            >
  // eslint-disable-next-line security/detect-object-injection
              {Array.from(grouped.entries()).map(([type, groupItems]) => (
                <li key={type} className="command-palette-group" role="presentation">
                  <div className="command-palette-group-header">
                    <Icon name={typeIcons.get(type) ?? 'file'} size={14} />
                    {typeLabels.get(type) ?? type}
                  </div>
                  <ul role="presentation">
                    {groupItems.map(item => {
                      const index = globalIndex++;
                      const selected = index === clampedIndex;
                      return (
                        <li
                          key={item.id}
                          id={`item-${item.id}`}
                          role="option"
                          aria-selected={selected}
                          data-selected={selected}
                          tabIndex={-1}
                          className={`command-palette-item ${selected ? 'selected' : ''}`}
                          onClick={() => handleSelect(item)}
                          onKeyDown={e => e.key === 'Enter' && handleSelect(item)}
                          onMouseEnter={() => setSelectedIndex(index)}
                        >
                          <div className="command-palette-item-content">
                            <span className="command-palette-item-title">{item.title}</span>
                            {item.subtitle && (
                              <span className="command-palette-item-subtitle">{item.subtitle}</span>
                            )}
                          </div>
                          {item.meta && (
                            <span className="command-palette-item-meta">{item.meta}</span>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="command-palette-footer">
          <span><kbd className="command-palette-kbd-sm">↑↓</kbd> Navigate</span>
          <span><kbd className="command-palette-kbd-sm">↵</kbd> Select</span>
          <span><kbd className="command-palette-kbd-sm">ESC</kbd> Close</span>
        </div>
      </div>
    </div>
  );
}
