import { useState, useEffect, useRef, useCallback, useMemo, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Command, CommandGroup, CommandList, CommandItem, CommandInput, CommandEmpty } from '@/components/ui-shadcn/command';
import { Icon } from '../ui/Icon';
import { globalSearch, type GlobalSearchResult } from '@/api/search';

export interface SearchableItem {
  id: string;
  type: 'target' | 'job' | 'finding' | 'page' | 'action';
  title: string;
  subtitle?: string;
  href?: string;
  meta?: string;
  action?: () => void;
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
  const [backendResults, setBackendResults] = useState<GlobalSearchResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!open) return;
    const tid = setTimeout(() => {
      setQuery('');
      setSelectedIndex(0);
      setRecentSearches(getRecentSearches());
      setBackendResults([]);
    }, 0);
    return () => clearTimeout(tid);
   
  }, [open]);

  useEffect(() => {
    if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    
    if (query.length < 2) {
      setBackendResults([]);
      setIsSearching(false);
      return;
    }

    setIsSearching(true);
    debounceTimerRef.current = setTimeout(async () => {
      try {
        const response = await globalSearch({ q: query, limit: 15 });
        setBackendResults(response.results);
      } catch {
        setBackendResults([]);
      } finally {
        setIsSearching(false);
      }
    }, 300);

    return () => {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    };
  }, [query]);

  const filtered = useMemo(() => {
    const localItems = query.length > 0
      ? items.filter(item =>
          item.title.toLowerCase().includes(query.toLowerCase()) ||
          (item.subtitle && item.subtitle.toLowerCase().includes(query.toLowerCase())) ||
          (item.meta && item.meta.toLowerCase().includes(query.toLowerCase()))
        )
      : [];

    const backendItems: SearchableItem[] = backendResults.map(r => ({
      id: `backend-${r.id}`,
      type: r.type,
      title: r.title,
      subtitle: r.subtitle,
      href: r.href,
      meta: r.meta,
    }));

    const seenIds = new Set(localItems.map(i => i.id));
    const uniqueBackend = backendItems.filter(i => !seenIds.has(i.id));

    return [...localItems, ...uniqueBackend];
  }, [items, query, backendResults]);

  const SECTION_MAP: Record<string, string> = {
    page: 'Navigation',
    action: 'Actions',
    target: 'Recent',
    job: 'Recent',
    finding: 'Recent',
  };

  const SECTION_ORDER = ['Navigation', 'Actions', 'Recent'];

  const grouped = useMemo(() => {
    const result = new Map<string, SearchableItem[]>();
    for (const item of filtered) {
      const section = SECTION_MAP[item.type] ?? 'Recent';
      const existing = result.get(section);
      if (existing) {
        existing.push(item);
      } else {
        result.set(section, [item]);
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
   
    ['action', 'Actions'],
  ]);

  const typeIcons = new Map<string, string>([
   
    ['target', 'target'],
   
    ['job', 'zap'],
   
    ['finding', 'shield'],
   
    ['page', 'file'],
   
    ['action', 'terminal'],
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
    if (item.action) {
      item.action();
    } else if (item.href) {
      navigate(item.href);
    }
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

  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());

  const toggleSection = useCallback((section: string) => {
    setCollapsedSections(prev => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  }, []);

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
      <Command className="command-palette"
        onClick={e => e.stopPropagation()}
        onKeyDown={e => e.stopPropagation()}
        tabIndex={0}
        shouldFilter={false}
      >
        <CommandInput
          placeholder="Search targets, jobs, findings..."
          value={query}
          onValueChange={v => { setQuery(v); setSelectedIndex(0); }}
          onKeyDown={handleKeyDown}
        />

        <CommandList>
          {query.length === 0 && recentSearches.length > 0 && (
            <div className="command-palette-empty">
              <h4 className="px-3 py-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">Recent Searches</h4>
              {recentSearches.slice(0, 5).map(r => (
                <CommandItem key={r} onSelect={() => setQuery(r)}>
                  <Icon name="clock" size={14} />
                  {r}
                </CommandItem>
              ))}
            </div>
          )}

          {query.length > 0 && flatResults.length === 0 && !isSearching && (
            <CommandEmpty>No results found</CommandEmpty>
          )}

          {isSearching && (
            <div className="command-palette-empty py-8 text-center text-sm text-muted-foreground">
              <Icon name="search" size={24} className="animate-pulse mx-auto mb-2" />
              <p>Searching...</p>
            </div>
          )}

          {flatResults.length > 0 && (
            <>
              {Array.from(grouped.entries()).map(([section, groupItems]) => {
                const isCollapsed = collapsedSections.has(section);
                return (
                  <div key={section}>
                    <button
                      className="flex w-full items-center gap-2 px-3 py-1.5 text-xs font-medium text-muted-foreground uppercase tracking-wider hover:text-foreground transition-colors"
                      onClick={() => toggleSection(section)}
                    >
                      <Icon name="chevron-right" size={12} className={`transition-transform ${isCollapsed ? '' : 'rotate-90'}`} />
                      {section}
                      <span className="ml-auto text-[10px] text-muted-foreground/60">{groupItems.length}</span>
                    </button>
                    {!isCollapsed && (
                      <CommandGroup>
                        {groupItems.map(item => {
                          const index = globalIndex++;
                          return (
                            <CommandItem
                              key={item.id}
                              value={item.id}
                              onSelect={() => handleSelect(item)}
                              onMouseEnter={() => setSelectedIndex(index)}
                            >
                              <div className="command-palette-item-content flex-1">
                                <span className="command-palette-item-title">{item.title}</span>
                                {item.subtitle && (
                                  <span className="command-palette-item-subtitle text-xs text-muted-foreground ml-2">{item.subtitle}</span>
                                )}
                              </div>
                              {item.meta && (
                                <span className="command-palette-item-meta text-[10px] text-muted-foreground">{item.meta}</span>
                              )}
                            </CommandItem>
                          );
                        })}
                      </CommandGroup>
                    )}
                  </div>
                );
              })}
            </>
          )}
        </CommandList>

        <div className="command-palette-footer border-t border-border px-3 py-2 flex gap-3 text-[10px] text-muted-foreground">
          <span><kbd className="command-palette-kbd-sm">↑↓</kbd> Navigate</span>
          <span><kbd className="command-palette-kbd-sm">↵</kbd> Select</span>
          <span><kbd className="command-palette-kbd-sm">ESC</kbd> Close</span>
        </div>
      </Command>
    </div>
  );
}
