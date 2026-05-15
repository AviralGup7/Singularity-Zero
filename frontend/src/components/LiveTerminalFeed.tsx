import { useRef, useState, memo, useMemo } from 'react';
import { Terminal, Minimize2, Pause, Play, Trash2, ChevronDown } from 'lucide-react';
import { Virtuoso, type VirtuosoHandle } from 'react-virtuoso';
import { useLiveTerminal } from '../hooks/useLiveTerminal';
import type { LiveTerminalLine } from '../hooks/useLiveTerminal';

// ─────────────────────────────────────────────────────────────────────────────
// Rendering Components
// ─────────────────────────────────────────────────────────────────────────────

const TerminalLineRow = memo(function TerminalLineRow({ 
  entry, 
  index 
}: { 
  entry: LiveTerminalLine; 
  index: number 
}) {
  const levelClass = useMemo(() => {
    switch (entry.level) {
      case 'critical': return 'text-red-500 font-bold bg-red-500/10 px-1';
      case 'error':    return 'text-red-400';
      case 'warn':     return 'text-yellow-400';
      case 'success':  return 'text-green-400';
      case 'system':   return 'text-blue-400 italic';
      case 'debug':    return 'text-muted/60 text-xs';
      default:         return 'text-cyan-400/90';
    }
  }, [entry.level]);

  return (
    <div 
      className="flex items-start gap-3 py-0.5 px-4 font-mono text-[13px] leading-relaxed border-l-2 border-transparent hover:bg-white/5 transition-colors group"
      style={{ borderLeftColor: entry.level === 'critical' ? 'var(--bad)' : 'transparent' }}
    >
      <span className="text-muted/40 select-none w-10 text-right shrink-0">{index + 1}</span>
      <span className="text-muted/50 shrink-0 whitespace-nowrap">{entry.timestamp}</span>
      {entry.jobId && (
        <span className="text-blue-500/50 shrink-0 select-none" title={`Job: ${entry.jobId}`}>
          [{entry.jobId.substring(0, 8)}]
        </span>
      )}
      <span className="text-accent/60 font-semibold shrink-0 w-24 overflow-hidden text-ellipsis whitespace-nowrap">
        {entry.module.toUpperCase()}
      </span>
      <span className={`break-all ${levelClass}`}>
        {entry.message}
      </span>
    </div>
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// Primary Component
// ─────────────────────────────────────────────────────────────────────────────

export function LiveTerminalFeed({
  className = '',
  autoStart = true,
  maxLines = 10000,
  jobId,
}: {
  className?: string;
  autoStart?: boolean;
  maxLines?: number;
  jobId?: string;
}) {
  const terminal = useLiveTerminal({ jobId, maxLines, autoConnect: autoStart });
  const { lines, activeJobs, isRunning, isLoading, connectionMode, currentJobId, actions } = terminal;

  const [isMinimized, setIsMinimized] = useState(false);
  const [showJobPicker, setShowJobPicker] = useState(false);
  const [followOutput, setFollowOutput] = useState(true);
  
  const virtuosoRef = useRef<VirtuosoHandle>(null);
  const pickerRef = useRef<HTMLDivElement>(null);

  // Memoized stats to prevent expensive recalculation on every line
  const stats = useMemo(() => ({
    critical: lines.filter(l => l.level === 'critical').length,
    error: lines.filter(l => l.level === 'error').length,
    warn: lines.filter(l => l.level === 'warn').length,
  }), [lines]);

  const currentJob = useMemo(() => 
    activeJobs.find(j => j.id === currentJobId) ?? activeJobs[0],
    [activeJobs, currentJobId]
  );

  const stageLabel = currentJob?.stage_label ?? currentJob?.stage ?? 'IDLE';
  const stagePct = currentJob?.stage_percent ?? currentJob?.progress_percent ?? null;

  // ── Minimized State ──────────────────────────────────────────────────
  if (isMinimized) {
    return (
      <div className={`fixed bottom-4 right-4 z-50 w-80 bg-black/90 border border-accent/30 shadow-2xl rounded-lg overflow-hidden cursor-pointer hover:border-accent/60 transition-all ${className}`} onClick={() => setIsMinimized(false)}>
        <div className="flex items-center gap-3 px-4 py-2 bg-accent/10">
          <Terminal size={14} className="text-accent" />
          <span className="text-xs font-bold text-accent uppercase tracking-widest flex-1">Terminal</span>
          <div className="flex gap-2 text-[10px]">
            {stats.critical > 0 && <span className="text-bad">{stats.critical} crit</span>}
            <span className="text-muted">{lines.length} L</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`flex flex-col h-[500px] bg-black/95 border border-line shadow-2xl rounded-xl overflow-hidden font-mono ${className}`}>
      {/* ── Dashboard Header ────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-4 py-3 bg-zinc-900/50 border-b border-line shrink-0">
        <div className="flex items-center gap-4 flex-1 overflow-hidden">
          <Terminal size={18} className="text-accent shrink-0" />
          
          <div className="relative" ref={pickerRef}>
            <button 
              onClick={() => setShowJobPicker(!showJobPicker)}
              className="flex items-center gap-2 px-3 py-1 bg-white/5 border border-white/10 rounded text-xs hover:bg-white/10 transition-colors max-w-[300px] overflow-hidden"
            >
              <span className="truncate">
                {currentJob ? `${currentJob.target_name || currentJob.id.slice(0,8)}` : 'Select Job'}
              </span>
              <ChevronDown size={14} className="text-muted" />
            </button>
            
            {showJobPicker && (
              <div className="absolute top-full left-0 mt-2 w-72 bg-zinc-900 border border-line rounded-lg shadow-2xl z-[100] py-2">
                {activeJobs.length === 0 && <div className="px-4 py-2 text-xs text-muted italic">No active jobs found</div>}
                {activeJobs.map(job => (
                  <button
                    key={job.id}
                    onClick={() => { actions.selectJob(job.id); setShowJobPicker(false); }}
                    className={`w-full text-left px-4 py-2 text-xs hover:bg-accent/10 flex flex-col gap-0.5 ${job.id === currentJobId ? 'bg-accent/5 border-l-2 border-accent' : ''}`}
                  >
                    <span className="font-bold text-text truncate">{job.target_name || 'Unnamed Target'}</span>
                    <span className="text-muted text-[10px] flex justify-between">
                      <span>{job.id.slice(0,8)} | {job.stage}</span>
                      <span>{job.progress_percent}%</span>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {currentJob && (
            <div className="flex items-center gap-3 ml-2 shrink-0">
              <span className="text-[10px] text-muted uppercase tracking-widest">{stageLabel}</span>
              {stagePct !== null && (
                <div className="w-24 h-1 bg-white/5 rounded-full overflow-hidden">
                  <div className="h-full bg-accent transition-all duration-500" style={{ width: `${stagePct}%` }} />
                </div>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center gap-4">
          <div className="flex gap-3 text-[10px] text-muted font-bold tracking-tighter shrink-0 uppercase">
            <span className={stats.error > 0 ? 'text-red-500' : ''}>ERR: {stats.error}</span>
            <span className={stats.critical > 0 ? 'text-bad' : ''}>CRIT: {stats.critical}</span>
            <span className={`px-1 rounded ${connectionMode === 'sse' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
              {connectionMode.toUpperCase()}
            </span>
          </div>

          <div className="flex items-center gap-1 border-l border-line pl-4">
             <button onClick={() => setFollowOutput(!followOutput)} className={`p-1.5 rounded hover:bg-white/5 ${followOutput ? 'text-accent' : 'text-muted'}`} title="Auto-scroll">
              <ChevronDown size={16} className={followOutput ? 'animate-bounce' : ''} />
            </button>
            <button onClick={() => isRunning ? actions.stop() : actions.start()} className="p-1.5 rounded hover:bg-white/5 text-muted" title={isRunning ? 'Pause' : 'Play'}>
              {isRunning ? <Pause size={16} /> : <Play size={16} />}
            </button>
            <button onClick={actions.clear} className="p-1.5 rounded hover:bg-white/5 text-muted" title="Clear Buffer">
              <Trash2 size={16} />
            </button>
            <button onClick={() => setIsMinimized(true)} className="p-1.5 rounded hover:bg-white/5 text-muted" title="Minimize">
              <Minimize2 size={16} />
            </button>
          </div>
        </div>
      </div>

      {/* ── Virtualized Log Body ───────────────────────────────────── */}
      <div className="flex-1 min-h-0 bg-[#020202] relative group/body">
        {isLoading && lines.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center z-10 bg-black/50">
            <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
          </div>
        )}
        
        {lines.length === 0 && !isLoading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-muted gap-4 opacity-30 select-none">
            <Terminal size={64} />
            <p className="text-xs uppercase tracking-[0.2em]">System Standby - No Logs</p>
          </div>
        )}

        <Virtuoso
          ref={virtuosoRef}
          data={lines}
          followOutput={followOutput ? 'smooth' : false}
          className="scrollbar-cyber"
          itemContent={(index: number, entry: LiveTerminalLine) => (
            <TerminalLineRow key={entry.id} entry={entry} index={index} />
          )}
          components={{
            Footer: () => isRunning ? (
              <div className="h-8 px-4 py-2 flex items-center gap-2">
                <span className="w-2 h-2 bg-accent rounded-full animate-pulse shadow-[0_0_8px_var(--accent)]" />
                <span className="text-[10px] text-accent/50 animate-pulse uppercase tracking-widest">Awaiting Transmission...</span>
              </div>
            ) : null
          }}
        />
      </div>

      {/* ── Footer ──────────────────────────────────────────────────── */}
      <div className="px-4 py-2 bg-zinc-900/80 border-t border-line flex justify-between items-center text-[10px] text-muted tracking-widest shrink-0">
        <div className="flex items-center gap-4">
          <span className={isRunning ? 'text-accent font-bold' : ''}>
            STATUS: {isRunning ? 'ACTIVE_MESH' : 'PAUSED'}
          </span>
          <span>BUFFER: {lines.length} / {maxLines}</span>
          {currentJob && <span className="text-accent/40 truncate max-w-[200px]">{currentJob.target_name}</span>}
        </div>
        <div className="flex gap-4">
          {currentJob?.elapsed_label && <span>TIME: {currentJob.elapsed_label}</span>}
          <span>ENGINE: V2.0.0-CORE</span>
        </div>
      </div>
    </div>
  );
}

export default LiveTerminalFeed;
