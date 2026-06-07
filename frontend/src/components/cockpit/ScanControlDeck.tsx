import type { CockpitNode } from '@/api/cockpit';

function metadataText(metadata: CockpitNode['metadata'], key: string): string {
  const value = metadata ? Reflect.get(metadata, key) : undefined;
  if (typeof value === 'string') return value;
  if (value == null) return '';
  return String(value);
}

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
  handleStopScan: () => void;
  handleRestartScan: () => void;
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
  handleStopScan,
  handleRestartScan,
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
}: ScanControlDeckProps) {
  const modules = [
    { id: 'subdomain_enum', label: 'Subdomain Recon' },
    { id: 'url_discovery', label: 'URL Discovery' },
    { id: 'port_scan', label: 'Port Scanning' },
    { id: 'httpx', label: 'HTTP Prober' },
    { id: 'nuclei', label: 'Vulnerability (Nuclei)' },
  ];

  return (
    <div className="absolute left-8 top-28 z-30 w-80 max-h-[calc(100vh-160px)] overflow-y-auto scrollbar-none rounded-xl border border-white/10 bg-black/80 p-5 shadow-[0_4px_30px_rgba(0,0,0,0.4)] backdrop-blur-xl transition-all">
      <div className="mb-4 flex items-center justify-between border-b border-white/5 pb-3">
        <div className="flex items-center gap-2">
          <div className="relative flex h-2 w-2">
            <span
              className={`absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping ${
                activeJob?.status === 'running'
                  ? 'bg-amber-400'
                  : activeJob?.status === 'completed'
                  ? 'bg-green-400'
                  : activeJob?.status === 'failed'
                  ? 'bg-red-400'
                  : activeJob?.status === 'stopped'
                  ? 'bg-rose-500'
                  : 'bg-slate-400'
              }`}
            />
            <span
              className={`relative inline-flex h-2 w-2 rounded-full ${
                activeJob?.status === 'running'
                  ? 'bg-amber-400 animate-pulse'
                  : activeJob?.status === 'completed'
                  ? 'bg-green-400 animate-pulse'
                  : activeJob?.status === 'failed'
                  ? 'bg-red-400 animate-pulse'
                  : activeJob?.status === 'stopped'
                  ? 'bg-rose-500'
                  : 'bg-slate-400'
              }`}
            />
          </div>
          <h3 className="font-sans text-[11px] font-black uppercase tracking-[0.2em] text-white">
            Pipeline Control Deck
          </h3>
        </div>

        <button
          type="button"
          onClick={() => setIsDeckOpen(!isDeckOpen)}
          className="text-[10px] font-mono uppercase tracking-widest text-accent hover:text-white transition-colors"
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
                    className="w-full rounded border border-white/10 bg-white/5 px-3 py-2 font-mono text-xs text-text placeholder-white/20 outline-none focus:border-accent/40 transition-colors"
                  />
                </label>
              </div>

              <div className="space-y-2">
                <div className="font-mono text-[9px] uppercase tracking-wider text-muted">Scan Mode Preset</div>
                <div className="flex flex-col gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setScanMode('safe');
                      setSelectedModules(['subdomain_enum', 'url_discovery', 'port_scan', 'httpx']);
                    }}
                    className={`flex flex-col items-start rounded-lg border p-3 text-left transition-all ${
                      scanMode === 'safe'
                        ? 'border-accent bg-accent/10 text-text shadow-[0_0_15px_rgba(0,255,244,0.15)]'
                        : 'border-white/5 bg-white/5 text-muted hover:bg-white/10 hover:border-white/10'
                    }`}
                  >
                    <span className="text-xs font-black uppercase tracking-wider text-white">Quick Health Check</span>
                    <span className="mt-0.5 text-[9px] font-medium leading-relaxed opacity-60">
                      safe, non-intrusive metadata audit
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setScanMode('aggressive');
                      setSelectedModules([
                        'subdomain_enum',
                        'url_discovery',
                        'port_scan',
                        'httpx',
                        'nuclei',
                      ]);
                    }}
                    className={`flex flex-col items-start rounded-lg border p-3 text-left transition-all ${
                      scanMode === 'aggressive'
                        ? 'border-accent bg-accent/10 text-text shadow-[0_0_15px_rgba(0,255,244,0.15)]'
                        : 'border-white/5 bg-white/5 text-muted hover:bg-white/10 hover:border-white/10'
                    }`}
                  >
                    <span className="text-xs font-black uppercase tracking-wider text-white">
                      Deep Security Clean-Up
                    </span>
                    <span className="mt-0.5 text-[9px] font-medium leading-relaxed opacity-60">
                      full active fuzzer checks
                    </span>
                  </button>
                </div>
              </div>

              <div className="space-y-2 border-t border-white/5 pt-3">
                <div className="font-mono text-[9px] uppercase tracking-widest text-muted">
                  Scan Tuning
                </div>
                <div className="space-y-3 rounded border border-white/5 bg-black/40 p-2.5 animate-fadeIn">
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
                        className="mt-1 w-full rounded border border-white/10 bg-white/5 px-2 py-1 font-mono text-[10px] text-text placeholder-white/20 outline-none focus:border-accent/40"
                      />
                    </label>
                    <p className="font-mono text-[8px] leading-snug text-muted/70">
                      One regex per line. Prevents scanners from logging you out, hitting
                      heavy endpoints, or visiting CDNs.
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-2 border-t border-white/5 pt-3">
                <button
                  type="button"
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="flex w-full items-center justify-between font-mono text-[9px] uppercase tracking-wider text-muted hover:text-accent transition-colors"
                >
                  <span>{showAdvanced ? '— Hide Modules' : '— Show Modules'}</span>
                </button>

                {showAdvanced && (
                  <div className="space-y-1 rounded border border-white/5 bg-black/40 p-2.5 mt-2 animate-fadeIn">
                    {modules.map((mod) => {
                      const active = selectedModules.includes(mod.id);
                      return (
                        <label
                          key={mod.id}
                          className="flex cursor-pointer items-center justify-between py-1 transition-colors hover:text-white"
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
                            className="h-3 w-3 rounded border-white/10 bg-black/40 text-accent outline-none accent-accent focus:ring-0"
                          />
                        </label>
                      );
                    })}
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={handleStartScan}
                disabled={launchingScan || !inputTarget.trim()}
                className="w-full rounded bg-accent py-2.5 text-center text-[10px] font-black uppercase tracking-[0.2em] text-black shadow-[0_0_15px_rgba(0,255,244,0.25)] transition-all hover:bg-white disabled:opacity-40 disabled:shadow-none"
              >
                {launchingScan ? 'ENGAGING ENGINE...' : 'ENGAGE SCAN ENGINE'}
              </button>
            </>
          ) : (
            <div className="space-y-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-mono text-[9px] uppercase tracking-wider text-muted">Active Pipeline</div>
                  <div className="font-mono text-[11px] font-bold text-text truncate max-w-[140px]">
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

                  <div className="relative h-2 w-full overflow-hidden rounded-full bg-white/10">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-400 shadow-[0_0_10px_rgba(0,255,244,0.4)]"
                      style={{ width: `${activeJob.progress_percent || 0}%` }}
                    />
                  </div>

                  <div className="flex items-center justify-between font-mono text-[8px] text-muted">
                    <span>PROGRESS</span>
                    <span>{Math.round(activeJob.progress_percent || 0)}%</span>
                  </div>
                </div>
              )}

              {activeJob.status_message && (
                <div className="rounded border border-cyan-500/10 bg-cyan-950/20 p-2.5 font-mono text-[9px] leading-relaxed text-cyan-200/90 max-h-24 overflow-y-auto">
                  <div className="font-bold text-cyan-400 mb-0.5">STATUS MESSAGE:</div>
                  {activeJob.status_message}
                </div>
              )}

              <div className="space-y-2 border-t border-white/5 pt-3">
                <div className="grid grid-cols-2 gap-2">
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
                    disabled={stoppingScan || !['running', 'pending'].includes(activeJob.status)}
                    className="flex items-center justify-center gap-1.5 rounded border border-rose-500/20 bg-rose-950/20 py-2 text-[9px] font-bold uppercase tracking-wider text-rose-400 transition-all hover:bg-rose-900/30 disabled:opacity-40"
                  >
                    <span className="icon-x" aria-hidden="true" />
                    {stoppingScan ? 'STOPPING...' : 'TERMINATE SCAN'}
                  </button>
                </div>

                <button
                  type="button"
                  onClick={onClearScan}
                  className="w-full rounded border border-white/10 bg-white/5 py-2 text-center text-[9px] font-bold uppercase tracking-widest text-muted hover:text-white transition-colors"
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
