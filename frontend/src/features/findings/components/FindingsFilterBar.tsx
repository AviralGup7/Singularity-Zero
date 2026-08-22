import { Search, Filter, X } from 'lucide-react';

interface FindingsFilterBarProps {
  searchQuery: string;
  onSearchChange: (value: string) => void;
  severityFilter: string[];
  onSeverityToggle: (severity: string) => void;
  onClearFilters: () => void;
  totalResults: number;
}

const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];

export function FindingsFilterBar({
  searchQuery,
  onSearchChange,
  severityFilter,
  onSeverityToggle,
  onClearFilters,
  totalResults,
}: FindingsFilterBarProps) {
  const hasActiveFilters = searchQuery !== '' || severityFilter.length > 0;

  return (
    <div className="findings-filter-compact bg-card border border-border rounded-xl p-4 mb-6 shadow-sm space-y-4" role="search">
      <div className="flex flex-col md:flex-row gap-4 items-stretch md:items-center justify-between">
        {/* Search Bar */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <label htmlFor="findings-filter-search" className="sr-only">Search findings</label>
          <input
            id="findings-filter-search"
            type="search"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search findings by title, CVE, host, or tool..."
            aria-label="Search findings by title, CVE, host, or tool"
            className="w-full pl-9 pr-4 py-2 bg-background border border-input rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => onSearchChange('')}
              aria-label="Clear search"
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Results Counter & Clear */}
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-muted-foreground">
            {totalResults} {totalResults === 1 ? 'finding' : 'findings'} found
          </span>

          {hasActiveFilters && (
            <button
              onClick={onClearFilters}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-destructive hover:bg-destructive/10 rounded-lg transition-colors"
            >
              <X className="w-3.5 h-3.5" />
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Severity Filter Badges */}
      <div className="flex items-center gap-2 flex-wrap pt-2 border-t border-border/50">
        <span className="text-xs text-muted-foreground font-medium flex items-center gap-1.5 mr-1">
          <Filter className="w-3.5 h-3.5" />
          Severity:
        </span>
        {SEVERITY_LEVELS.map((level) => {
          const isSelected = severityFilter.includes(level);
          return (
            <button
              key={level}
              type="button"
              onClick={() => onSeverityToggle(level)}
              aria-pressed={isSelected}
              className={`px-2.5 py-1 rounded-full text-xs font-semibold uppercase tracking-wider transition-all ${
                isSelected
                  ? 'bg-primary text-primary-foreground shadow-sm'
                  : 'bg-muted/50 text-muted-foreground hover:bg-muted hover:text-foreground'
              }`}
            >
              {level}
            </button>
          );
        })}
      </div>
    </div>
  );
}
