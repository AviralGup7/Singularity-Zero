import { memo, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { parseFindingTimestamp } from '@/utils/findingTime';
import { Virtuoso } from 'react-virtuoso';
import { Shield, ExternalLink, Clock, CheckSquare, Square } from 'lucide-react';
import type { Finding } from '@/types/api';

// ─────────────────────────────────────────────────────────────────────────────
// High-Performance Row Component
// ─────────────────────────────────────────────────────────────────────────────

const FindingRow = memo(function FindingRow({ 
  finding,
  isSelected,
  onToggleSelect,
  selectionMode,
}: { 
  finding: Finding;
  isSelected?: boolean;
  onToggleSelect?: (id: string) => void;
  selectionMode?: boolean;
}) {
  let severityClass = 'border-l-info bg-info/5';
  switch (finding.severity) {
    case 'critical': severityClass = 'border-l-critical bg-critical/5'; break;
    case 'high':     severityClass = 'border-l-high bg-high/5'; break;
    case 'medium':   severityClass = 'border-l-medium bg-medium/5'; break;
    case 'low':      severityClass = 'border-l-low bg-low/5'; break;
    default: break;
  }

  const initials = finding.target?.substring(0, 2).toUpperCase() || '??';
  const timestamp = parseFindingTimestamp(finding.timestamp) || null;

  return (
    <div className="px-4 py-2">
      <div className={`flex items-center gap-4 p-4 rounded-xl border border-line border-l-4 ${severityClass} hover:border-accent/40 transition-all group cursor-pointer glass-panel`}>
        {selectionMode && (
          <button
            type="button"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onToggleSelect?.(finding.id);
            }}
            className="shrink-0 text-muted hover:text-accent transition-colors"
            aria-label={isSelected ? `Deselect finding ${finding.title}` : `Select finding ${finding.title}`}
          >
            {isSelected ? <CheckSquare size={16} className="text-accent" /> : <Square size={16} />}
          </button>
        )}
        <div className="shrink-0 w-10 h-10 rounded-lg bg-zinc-900 border border-line flex items-center justify-center font-black text-xs text-muted group-hover:text-accent transition-colors">
          {initials}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded ${
              finding.severity === 'critical' ? 'bg-critical text-text-primary' : 
              finding.severity === 'high' ? 'bg-high text-text-primary' : 
              'bg-zinc-800 text-muted'
            }`}>
              {finding.severity}
            </span>
            <h4 className="text-sm font-bold text-text truncate leading-none">{finding.title}</h4>
          </div>
          
          <div className="flex items-center gap-3 text-[10px] text-muted font-mono">
            <span className="flex items-center gap-1"><Shield size={10} /> {finding.type}</span>
            <span className="flex items-center gap-1 max-w-[200px] truncate"><ExternalLink size={10} /> {finding.url || finding.host}</span>
          </div>
        </div>

        <div className="shrink-0 flex items-center gap-6 pr-4">
          <div className="flex flex-col items-end">
            <span className="text-[10px] text-text-primary font-bold">{Math.round(finding.confidence * 100)}%</span>
            <span className="text-[9px] text-muted uppercase tracking-tighter">Confidence</span>
          </div>
          <div className="w-px h-8 bg-surface-hover" />
          <div className="text-right">
            <div className="text-[10px] text-muted flex items-center gap-1 justify-end">
              <Clock size={10} /> {timestamp !== null ? new Date(timestamp).toLocaleDateString() : 'Unknown'}
            </div>
            <div className="text-[9px] text-accent uppercase tracking-widest font-black">
              {finding.lifecycle_state}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
});

const FindingHeader = memo(function FindingHeader({ count }: { count: number }) {
  return (
    <div className="px-6 py-4 flex justify-between items-center bg-surface-2 border-b border-line sticky top-0 z-10 backdrop-blur-md">
      <span className="text-[10px] font-black text-muted uppercase tracking-widest">
        Aggregated Intelligence Grid ({count} points)
      </span>
      <div className="flex gap-4 text-[9px] text-muted uppercase">
        <span>Filter: All</span>
        <span>Sort: Severity</span>
      </div>
    </div>
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// Virtualized List Container
// ─────────────────────────────────────────────────────────────────────────────

interface VirtualizedFindingsListProps {
  findings: Finding[];
  height?: number | string;
  onSelect?: (finding: Finding) => void;
  selectedIds?: Set<string>;
  onToggleSelect?: (id: string) => void;
  selectionMode?: boolean;
}

export const VirtualizedFindingsList = memo(function VirtualizedFindingsList({
  findings,
  height = '600px',
  onSelect,
  selectedIds,
  onToggleSelect,
  selectionMode = false,
}: VirtualizedFindingsListProps) {
   
  const headerCount = findings.length;
  const Header = useMemo(() => {
    function ListHeader() {
      return <FindingHeader count={headerCount} />;
    }
    return ListHeader;
  }, [headerCount]);

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-muted opacity-30 gap-4">
        <Shield size={48} strokeWidth={1} />
        <p className="text-xs uppercase tracking-[0.2em]">Scan Grid Clear - No Findings</p>
      </div>
    );
  }

  return (
    <div style={{ height }} className="w-full relative">
      <Virtuoso
        data={findings}
        useWindowScroll={false}
        className="scrollbar-cyber"
        itemContent={(_index: number, finding: Finding) => (
          <Link
            to={`/findings?finding=${encodeURIComponent(finding.id)}`}
            className="w-full text-left block focus:outline-none"
            aria-label={`Open finding ${finding.title || finding.id}`}
            onClick={(e) => {
              if (!onSelect) return;
              e.preventDefault();
              onSelect(finding);
            }}
            key={finding.id}
          >
            <FindingRow 
              finding={finding} 
              isSelected={selectedIds?.has(finding.id)}
              onToggleSelect={onToggleSelect}
              selectionMode={selectionMode}
            />
          </Link>
        )}
        components={{
          Header
        }}
      />
    </div>
  );
});

export default VirtualizedFindingsList;
