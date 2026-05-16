import { memo, useMemo, useCallback } from 'react';
import { Virtuoso } from 'react-virtuoso';
import { Shield, ExternalLink, Clock } from 'lucide-react';
import type { Finding } from '../types/api';

// ─────────────────────────────────────────────────────────────────────────────
// High-Performance Row Component
// ─────────────────────────────────────────────────────────────────────────────

const FindingRow = memo(function FindingRow({ 
  finding 
}: { 
  finding: Finding; 
}) {
  const severityClass = useMemo(() => {
    switch (finding.severity) {
      case 'critical': return 'border-l-critical bg-critical/5';
      case 'high':     return 'border-l-high bg-high/5';
      case 'medium':   return 'border-l-medium bg-medium/5';
      case 'low':      return 'border-l-low bg-low/5';
      default:         return 'border-l-info bg-info/5';
    }
   
  }, [finding.severity]);

  const initials = finding.target?.substring(0, 2).toUpperCase() || '??';

  const timestamp = typeof finding.timestamp === 'number' ? finding.timestamp * 1000 : Date.parse(finding.timestamp);

  return (
    <div className="px-4 py-2">
      <div className={`flex items-center gap-4 p-4 rounded-xl border border-white/5 border-l-4 ${severityClass} hover:border-white/10 transition-all group cursor-pointer glass-panel`}>
        <div className="shrink-0 w-10 h-10 rounded-lg bg-zinc-900 border border-white/10 flex items-center justify-center font-black text-xs text-muted group-hover:text-accent transition-colors">
          {initials}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
  // eslint-disable-next-line security/detect-object-injection
            <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded ${
              finding.severity === 'critical' ? 'bg-critical text-white' : 
              finding.severity === 'high' ? 'bg-high text-white' : 
              'bg-zinc-800 text-muted'
            }`}>
              {finding.severity}
            </span>
            <h4 className="text-sm font-bold text-text truncate leading-none">{finding.title}</h4>
          </div>
          
  // eslint-disable-next-line security/detect-object-injection
          <div className="flex items-center gap-3 text-[10px] text-muted font-mono">
            <span className="flex items-center gap-1"><Shield size={10} /> {finding.type}</span>
  // eslint-disable-next-line security/detect-object-injection
            <span className="flex items-center gap-1 max-w-[200px] truncate"><ExternalLink size={10} /> {finding.url || finding.host}</span>
          </div>
        </div>

        <div className="shrink-0 flex items-center gap-6 pr-4">
          <div className="flex flex-col items-end">
  // eslint-disable-next-line security/detect-object-injection
            <span className="text-[10px] text-white font-bold">{Math.round(finding.confidence * 100)}%</span>
  // eslint-disable-next-line security/detect-object-injection
            <span className="text-[9px] text-muted uppercase tracking-tighter">Confidence</span>
          </div>
          <div className="w-px h-8 bg-white/5" />
          <div className="text-right">
  // eslint-disable-next-line security/detect-object-injection
            <div className="text-[10px] text-muted flex items-center gap-1 justify-end">
              <Clock size={10} /> {new Date(timestamp).toLocaleDateString()}
            </div>
  // eslint-disable-next-line security/detect-object-injection
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
    <div className="px-6 py-4 flex justify-between items-center bg-black/40 border-b border-white/5 sticky top-0 z-10 backdrop-blur-md">
  // eslint-disable-next-line security/detect-object-injection
      <span className="text-[10px] font-black text-muted uppercase tracking-widest">
        Aggregated Intelligence Grid ({count} points)
      </span>
  // eslint-disable-next-line security/detect-object-injection
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
}

export const VirtualizedFindingsList = memo(function VirtualizedFindingsList({
  findings,
  height = '600px',
  onSelect
}: VirtualizedFindingsListProps) {
   
  const Header = useCallback(() => <FindingHeader count={findings.length} />, [findings.length]);

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-muted opacity-30 gap-4">
        <Shield size={48} strokeWidth={1} />
  // eslint-disable-next-line security/detect-object-injection
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
          <div onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLElement).click()} onClick={() => onSelect?.(finding)} key={finding.id}>
            <FindingRow finding={finding} />
          </div>
        )}
        components={{
          Header
        }}
      />
    </div>
  );
});

export default VirtualizedFindingsList;
