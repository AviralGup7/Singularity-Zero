import { useState, useEffect } from 'react';
import { getProjects  } from '@/api/projects';
import type {Project} from '@/api/projects';

interface SliderRowProps {
  label: string;
  value: number;
  onChange: (n: number) => void;
  min: number;
  max: number;
  step: number;
  suffix?: string;
  hint?: string;
}

function SliderRow({ label, value, onChange, min, max, step, suffix, hint }: SliderRowProps) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between font-mono text-[9px] uppercase tracking-wider text-muted">
        <span>{label}</span>
        <span className="font-bold text-accent">
          {value} {suffix ?? ''}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="cockpit-slider w-full"
        aria-label={label}
      />
      {hint && <p className="font-mono text-[8px] leading-snug text-muted/70">{hint}</p>}
    </div>
  );
}

interface ScanControlDeckProps {
  activeJob: { status?: string; stage_label?: string; progress_percent?: number; base_url?: string; status_message?: string } | null;
  activeJobId: string | undefined;
  isDeckOpen: boolean;
  setIsDeckOpen: (open: boolean) => void;
  scanMode: 'safe' | 'aggressive';
  setScanMode: (mode: 'safe' | 'aggressive') => void;
  selectedModules: string[];
  setSelectedModules: (modules: string[]) => void;
  showAdvanced: boolean;
  setShowAdvanced: (show: boolean) => void;
  launchingScan: boolean;
  handleStartScan: () => void;
  stoppingScan: boolean;
  restartingScan: boolean;
  pausingScan: boolean;
  resumingScan: boolean;
  handleStopScan: () => void;
  handleRestartScan: () => void;
  handlePauseScan: () => void;
  handleResumeScan: () => void;
  inputTarget: string;
  setInputTarget: (target: string) => void;
  onClearScan: () => void;
  scanDepth: number;
  setScanDepth: (n: number) => void;
  scanConcurrency: number;
  setScanConcurrency: (n: number) => void;
  scanRateLimit: number;
  setScanRateLimit: (n: number) => void;
  excludedPaths: string;
  setExcludedPaths: (s: string) => void;
  selectedProject: Project | null;
  setSelectedProject: (project: Project | null) => void;
  className?: string;
}

export function ScanControlDeck({
  activeJob,
  activeJobId,
  isDeckOpen,
  setIsDeckOpen,
  scanMode,
  setScanMode,
  selectedModules,
  setSelectedModules,
  showAdvanced,
  setShowAdvanced,
  launchingScan,
  handleStartScan,
  stoppingScan,
  restartingScan,
  pausingScan,
  resumingScan,
  handleStopScan,
  handleRestartScan,
  handlePauseScan,
  handleResumeScan,
  inputTarget,
  setInputTarget,
  onClearScan,
  scanDepth,
  setScanDepth,
  scanConcurrency,
  setScanConcurrency,
  scanRateLimit,
  setScanRateLimit,
  excludedPaths,
  setExcludedPaths,
  selectedProject,
  setSelectedProject,
  className,
}: ScanControlDeckProps) {
  const [showTuning, setShowTuning] = useState(false);
  const [projects, setProjects] = useState<Project[]>([]);
  const [showProjects, setShowProjects] = useState(false);

  useEffect(() => {
    getProjects().then(setProjects).catch(() => {});
  }, []);
  const modules = [
    { id: 'subfinder', label: 'Subdomain Recon (subfinder)' },
    { id: 'httpx', label: 'HTTP Prober' },
    { id: 'gau', label: 'URL Discovery (gau)' },
    { id: 'katana', label: 'Crawler (katana)' },
    { id: 'nuclei', label: 'Vulnerability (Nuclei)' },
  ];

  return (
    <div className={className ?? "absolute left-8 top-28 z-30 w-80 max-h-[calc(100vh-160px)] overflow-y-auto scrollbar-cyber rounded-xl border border-line-strong bg-surface/80 p-5 shadow-panel-glass backdrop-blur-xl transition-all"}>
              <div className="mb-4 flex items-center justify-between border-b border-line-muted pb-3">
        <div className="flex items-center gap-2">
          <div className="relative flex h-2 w-2">
            <span
              className={`absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping ${
                activeJob?.status === 'running'
                  ? 'bg-warn'
                  : activeJob?.status === 'completed'
                  ? 'bg-ok'
                  : activeJob?.status === 'failed'
                  ? 'bg-bad'
                  : activeJob?.status === 'stopped'
                  ? 'bg-bad'
                  : 'bg-text-tertiary'
              }`}
            />
            <span
              className={`relative inline-flex h-2 w-2 rounded-full ${
                activeJob?.status === 'running'
                  ? 'bg-warn animate-pulse'
                  : activeJob?.status === 'completed'
                  ? 'bg-ok animate-pulse'
                  : activeJob?.status === 'failed'
                  ? 'bg-bad animate-pulse'
                  : activeJob?.status === 'stopped'
                  ? 'bg-bad'
                  : 'bg-text-tertiary'
              }`}
            />
          </div>
          <h3 className="font-sans text-[11px] font-black uppercase tracking-[0.2em] text-text-primary">
            Pipeline Control Deck
          </h3>
        </div>

        <button
          type="button"
          onClick={() => setIsDeckOpen(!isDeckOpen)}
          className="text-[10px] font-mono uppercase tracking-widest text-accent hover:text-text-primary transition-colors"
        >
          {isDeckOpen ? '[ Collapse ]' : '[ Expand ]'}
        </button>
      </div>

      {isDeckOpen && (
        <div className="space-y-4">
          {!activeJobId || !activeJob ? (
            <>
              <div className="space-y-1">
                <label className="block space-y-1">
                  <span className="font-mono text-[9px] uppercase tracking-wider text-muted">
                    Enter your website URL to scan.
                  </span>
                  <input
                    type="text"
                    value={inputTarget}
                    onChange={(e) => setInputTarget(e.target.value)}
                    placeholder="e.g. https://example.com"
                    className="w-full rounded border border-line bg-surface-hover px-3 py-2 font-mono text-xs text-text-primary placeholder:text-text-tertiary/40 outline-none focus:border-accent/40 transition-colors"
                  />
                </label>
              </div>

              {projects.length > 0 && (
                <div className="space-y-2">
                  <button
                    type="button"
                    onClick={() => setShowProjects(!showProjects)}
                    className="flex w-full items-center justify-between font-mono text-[9px] uppercase tracking-wider text-muted hover:text-accent transition-colors"
                  >
                    <span>{selectedProject ? `Project: ${selectedProject.name}` : '+ Quick Launch Projects'}</span>
                    {selectedProject && (
                      <span
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedProject(null);
                        }}
                        className="text-bad hover:text-bad/80"
                      >
                        [clear]
                      </span>
                    )}
                  </button>

                  {showProjects && !selectedProject && (
                    <div className="space-y-1.5 rounded border border-line-muted bg-surface/40 p-2.5 animate-fadeIn">
                      {projects.map((project) => (
                        <button
                          key={project.id}
                          type="button"
                          onClick={() => {
                            setSelectedProject(project);
                            setShowProjects(false);
                          }}
                          className="w-full rounded border border-line-muted bg-surface-hover p-2.5 text-left transition-all hover:bg-accent/10 hover:border-accent/30"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-[10px] font-bold text-text-primary">{project.name}</span>
                            {project.rewards && (
                              <span className="font-mono text-[8px] text-accent">{project.rewards}</span>
                            )}
                          </div>
                          {project.description && (
                            <p className="mt-1 font-mono text-[8px] leading-relaxed text-muted/70 line-clamp-2">
                              {project.description}
                            </p>
                          )}
                          {project.scope && (
                            <p className="mt-1 font-mono text-[8px] text-muted/50">
                              Scope: {project.scope}
                            </p>
                          )}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div className="space-y-2">
                <div className="font-mono text-[9px] uppercase tracking-wider text-muted">Scan Mode Preset</div>
                <div className="flex gap-2" role="radiogroup" aria-label="Scan mode preset">
                  <button
                    type="button"
                    onClick={() => {
                      setScanMode('safe');
                      setSelectedModules(['subfinder', 'httpx', 'gau']);
                    }}
                    role="radio"
                    aria-checked={scanMode === 'safe'}
                    className={`flex-1 flex flex-col items-start rounded-lg border p-2.5 text-left transition-all ${
                      scanMode === 'safe'
                        ? 'border-accent bg-accent-soft text-text-primary shadow-glow-accent-sm'
                        : 'border-line-muted bg-surface-hover text-text-secondary hover:bg-surface-2 hover:border-line'
                    }`}
                  >
                    <span className="text-[10px] font-black uppercase tracking-wider text-text-primary">Safe Preset</span>
                    <span className="mt-0.5 text-[8px] leading-relaxed opacity-60">
                      Recon & Metadata
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setScanMode('aggressive');
                      setSelectedModules([
                        'subfinder',
                        'httpx',
                        'gau',
                        'katana',
                        'nuclei',
                      ]);
                    }}
                    role="radio"
                    aria-checked={scanMode === 'aggressive'}
                    className={`flex-1 flex flex-col items-start rounded-lg border p-2.5 text-left transition-all ${
                      scanMode === 'aggressive'
                        ? 'border-accent bg-accent-soft text-text-primary shadow-glow-accent-sm'
                        : 'border-line-muted bg-surface-hover text-text-secondary hover:bg-surface-2 hover:border-line'
                    }`}
                  >
                    <span className="text-[10px] font-black uppercase tracking-wider text-text-primary">Deep Preset</span>
                    <span className="mt-0.5 text-[8px] leading-relaxed opacity-60">
                      Active Vulnerability
                    </span>
                  </button>
                </div>
              </div>

              <div className="space-y-2 border-t border-line-muted pt-3">
                <button
                  type="button"
                  onClick={() => setShowTuning(!showTuning)}
                  className="flex w-full items-center justify-between font-mono text-[9px] uppercase tracking-wider text-muted hover:text-accent transition-colors"
                >
                  <span>{showTuning ? '— Hide Tuning & Paths' : '+ Show Tuning & Paths'}</span>
                </button>

                {showTuning && (
                  <div className="space-y-3 rounded border border-line-muted bg-surface/40 p-2.5 animate-fadeIn">
                    <SliderRow
                      label="Crawl Depth"
                      min={1}
                      max={8}
                      step={1}
                      value={scanDepth}
                      onChange={setScanDepth}
                      suffix={`level${scanDepth === 1 ? '' : 's'}`}
                      hint="How deep the crawler follows links before stopping"
                    />
                    <SliderRow
                      label="Concurrency"
                      min={1}
                      max={64}
                      step={1}
                      value={scanConcurrency}
                      onChange={setScanConcurrency}
                      suffix="workers"
                      hint="Parallel in-flight requests (raise carefully, may trigger WAFs)"
                    />
                    <SliderRow
                      label="Rate Limit"
                      min={1}
                      max={500}
                      step={1}
                      value={scanRateLimit}
                      onChange={setScanRateLimit}
                      suffix="req/s"
                      hint="Requests per second cap — tune to match program policy"
                    />
                    <div className="space-y-1">
                      <label className="block">
                        <span className="font-mono text-[9px] uppercase tracking-wider text-muted">
                          Excluded paths
                        </span>
                        <textarea
                          value={excludedPaths}
                          onChange={(e) => setExcludedPaths(e.target.value)}
                          rows={2}
                          placeholder="/logout, /signout, .*\\.gif$"
                          className="mt-1 w-full rounded border border-line bg-surface-hover px-2 py-1 font-mono text-[10px] text-text-primary placeholder:text-text-tertiary/40 outline-none focus:border-accent/40"
                        />
                      </label>
                      <p className="font-mono text-[8px] leading-snug text-muted/70">
                        One regex per line. Prevents scanners from logging you out, hitting
                        heavy endpoints, or visiting CDNs.
                      </p>
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-2 border-t border-line-muted pt-3">
                <button
                  type="button"
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="flex w-full items-center justify-between font-mono text-[9px] uppercase tracking-wider text-muted hover:text-accent transition-colors"
                >
                  <span>{showAdvanced ? '— Hide Modules' : '— Show Modules'}</span>
                </button>

                {showAdvanced && (
                  <div className="space-y-1 rounded border border-line-muted bg-surface/40 p-2.5 mt-2 animate-fadeIn">
                    {modules.map((mod) => {
                      const active = selectedModules.includes(mod.id);
                      return (
                        <label
                          key={mod.id}
                          className="flex cursor-pointer items-center justify-between py-1 transition-colors hover:text-text-primary"
                        >
                          <span className="font-mono text-[10px] text-muted-foreground">{mod.label}</span>
                          <input
                            type="checkbox"
                            checked={active}
                            onChange={() => {
                              if (active) {
                                setSelectedModules(selectedModules.filter((m) => m !== mod.id));
                              } else {
                                setSelectedModules([...selectedModules, mod.id]);
                              }
                            }}
                            className="h-3 w-3 rounded border-line bg-surface/40 text-accent outline-none accent-accent focus:ring-0"
                          />
                        </label>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="sticky bottom-0 bg-surface/95 pt-3 border-t border-line-muted -mx-5 -mb-5 px-5 pb-5 z-10 backdrop-blur-md">
                <button
                  type="button"
                  onClick={handleStartScan}
                  disabled={launchingScan || !inputTarget.trim()}
                  className="w-full rounded bg-accent py-2.5 text-center text-[10px] font-black uppercase tracking-[0.2em] text-black shadow-glow-accent-md transition-all hover:bg-surface-raised disabled:opacity-40 disabled:shadow-none"
                >
                  {launchingScan ? 'ENGAGING ENGINE...' : 'ENGAGE SCAN ENGINE'}
                </button>
              </div>
            </>
          ) : (
              <div className="space-y-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-mono text-[9px] uppercase tracking-wider text-muted">Active Pipeline</div>
                  <div className="font-mono text-[11px] font-bold text-text truncate max-w-[140px]" title={activeJob.base_url ?? ''}>
                    {activeJob.base_url}
                  </div>
                </div>
                <div className="text-right">
                  <div className="font-mono text-[9px] uppercase tracking-wider text-muted">Engine State</div>
                  <div className="font-mono text-[10px] font-bold uppercase text-accent">{activeJob.status}</div>
                </div>
              </div>

              {activeJob.stage_label && (
                <div className="space-y-1">
                  <div className="flex items-center justify-between font-mono text-[9px]">
                    <span className="uppercase text-muted">Current Stage</span>
                    <span className="font-bold text-text">{activeJob.stage_label}</span>
                  </div>

                  <div className="relative h-2 w-full overflow-hidden rounded-full bg-surface-2" role="progressbar" aria-valuenow={Math.round(activeJob.progress_percent || 0)} aria-valuemin={0} aria-valuemax={100} aria-label={`Scan progress: ${Math.round(activeJob.progress_percent || 0)}%`}>
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-info via-accent to-ok shadow-glow-ok-sm"
                      style={{ width: `${activeJob.progress_percent || 0}%` }}
                    />
                  </div>

                  <div className="flex items-center justify-between font-mono text-[8px] text-muted">
                    <span>PROGRESS</span>
                    <span className="tabular-nums">{Math.round(activeJob.progress_percent || 0)}%</span>
                  </div>
                </div>
              )}

              {activeJob.status_message && (
                <div className="rounded border border-info/10 bg-info/5 p-2.5 font-mono text-[9px] leading-relaxed text-info max-h-24 overflow-y-auto">
                  <div className="font-bold text-info mb-0.5">STATUS MESSAGE:</div>
                  {activeJob.status_message}
                </div>
              )}

              <div className="space-y-2 border-t border-line-muted pt-3">
                <div className="grid grid-cols-3 gap-2">
                  {activeJob.status === 'running' ? (
                    <button
                      type="button"
                      onClick={handlePauseScan}
                      disabled={pausingScan}
                      className="flex items-center justify-center gap-1.5 rounded border border-warn/20 bg-warn/5 py-2 text-[9px] font-bold uppercase tracking-wider text-warn transition-all hover:bg-warn/10 disabled:opacity-40"
                    >
                      {pausingScan ? 'PAUSING...' : 'PAUSE SCAN'}
                    </button>
                  ) : activeJob.status === 'paused' ? (
                    <button
                      type="button"
                      onClick={handleResumeScan}
                      disabled={resumingScan}
                      className="flex items-center justify-center gap-1.5 rounded border border-accent/20 bg-accent/5 py-2 text-[9px] font-bold uppercase tracking-wider text-accent transition-all hover:bg-accent/15 disabled:opacity-40"
                    >
                      {resumingScan ? 'RESUMING...' : 'RESUME SCAN'}
                    </button>
                  ) : (
                    <button
                      type="button"
                      disabled
                      className="flex items-center justify-center gap-1.5 rounded border border-line-muted bg-surface-hover py-2 text-[9px] font-bold uppercase tracking-wider text-muted opacity-40"
                    >
                      PAUSE
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={handleRestartScan}
                    disabled={restartingScan || activeJob.status !== 'running'}
                    className="flex items-center justify-center gap-1.5 rounded border border-accent/20 bg-accent/5 py-2 text-[9px] font-bold uppercase tracking-wider text-accent transition-all hover:bg-accent/15 disabled:opacity-40"
                  >
                    <span className="icon-activity" aria-hidden="true" />
                    {restartingScan ? 'RESTARTING...' : 'RESTART SAFE'}
                  </button>
                  <button
                    type="button"
                    onClick={handleStopScan}
                    disabled={stoppingScan || !activeJob.status || !['running', 'pending', 'paused'].includes(activeJob.status)}
                    className="flex items-center justify-center gap-1.5 rounded border border-bad/20 bg-bad/5 py-2 text-[9px] font-bold uppercase tracking-wider text-bad transition-all hover:bg-bad/10 disabled:opacity-40"
                  >
                    <span className="icon-x" aria-hidden="true" />
                    {stoppingScan ? 'STOPPING...' : 'TERMINATE SCAN'}
                  </button>
                </div>

                <button
                  type="button"
                  onClick={onClearScan}
                  className="w-full rounded border border-line bg-surface-hover py-2 text-center text-[9px] font-bold uppercase tracking-widest text-text-secondary hover:text-text-primary transition-colors"
                >
                  Clear / New Scan
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
