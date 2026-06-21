import { memo, useState, useEffect } from 'react';
import { Icon } from '@/components/ui/Icon';
import type { Project } from '@/api/projects';
import { getProjects } from '@/api/projects';

interface CockpitSetupViewProps {
  inputTarget: string;
  setInputTarget: (target: string) => void;
  scanMode: 'safe' | 'aggressive';
  setScanMode: (mode: 'safe' | 'aggressive') => void;
  onStartScan: () => void;
  launchingScan: boolean;
  setSelectedModules: (modules: string[]) => void;
  selectedProject: Project | null;
  setSelectedProject: (project: Project | null) => void;
  scanDepth: number;
  setScanDepth: (depth: number) => void;
  scanConcurrency: number;
  setScanConcurrency: (concurrency: number) => void;
}

function CockpitSetupViewBase({
  inputTarget,
  setInputTarget,
  scanMode,
  setScanMode,
  onStartScan,
  launchingScan,
  setSelectedModules,
  selectedProject,
  setSelectedProject,
  scanDepth,
  setScanDepth,
  scanConcurrency,
  setScanConcurrency,
}: CockpitSetupViewProps) {
  const [projectsList, setProjectsList] = useState<Project[]>([]);

  useEffect(() => {
    getProjects().then(setProjectsList).catch(() => {});
  }, []);

  return (
    <div className="relative flex h-full w-full flex-col overflow-y-auto bg-[#05070a] p-8 cyber-grid-overlay scrollbar-cyber">
      <div className="pointer-events-none absolute inset-0 z-0 opacity-15 overflow-hidden">
        <div className="absolute top-1/2 left-1/2 w-[60vw] h-[60vw] -translate-x-1/2 -translate-y-1/2 rounded-full border border-accent/20">
          <div className="radar-sweep-indicator absolute inset-0 rounded-full bg-gradient-to-tr from-accent/10 to-transparent" />
        </div>
      </div>

      <div className="relative z-10 m-auto flex w-full max-w-4xl flex-col items-center justify-center py-12">
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-950/20 px-3 py-1 font-mono text-[10px] uppercase tracking-widest text-cyan-400">
            <span className="pulse-dot bg-cyan-400" /> SYSTEM STANDBY: READY FOR TELEMETRY
          </div>
          <h1 className="mt-4 text-4xl font-extrabold tracking-tighter text-white uppercase sm:text-5xl">
            CYBER STEERING COCKPIT
          </h1>
          <p className="mt-2 text-sm text-muted font-mono max-w-xl mx-auto leading-relaxed">
            Launch multi-stage distributed security scan engines. Graph and simulate target attack-chains and live forensic telemetry.
          </p>
        </div>

        <div className="w-full rounded-2xl border border-white/10 bg-[#0c0f16]/85 p-6 shadow-2xl backdrop-blur-xl md:p-8">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="space-y-6">
              <div>
                <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-white mb-2 flex items-center gap-2">
                  <Icon name="target" size={14} className="text-accent" /> Scan Target URI
                </h3>
                <input
                  type="text"
                  value={inputTarget}
                  onChange={(e) => setInputTarget(e.target.value)}
                  placeholder="e.g. https://example.com"
                  className="w-full rounded-lg border border-white/10 bg-white/5 px-4 py-3 font-mono text-xs text-text placeholder-white/20 outline-none focus:border-accent/40 focus:ring-1 focus:ring-accent/40 transition-all shadow-inner"
                />
                <p className="mt-1.5 font-mono text-[9px] text-muted leading-relaxed">
                  Ensure the domain lies within your compliance program boundaries.
                </p>
              </div>

              {projectsList.length > 0 && (
                <div>
                  <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-white mb-2">
                    Active Bounty Programs
                  </h3>
                  <div className="grid grid-cols-1 gap-2 max-h-48 overflow-y-auto scrollbar-cyber rounded border border-white/5 bg-black/30 p-2">
                    {projectsList.map((project) => (
                      <button
                        key={project.id}
                        type="button"
                        onClick={() => {
                          setSelectedProject(project);
                          setInputTarget(`https://${project.scope.split(',')[0].trim().replace('*.', '')}`);
                        }}
                        className={`w-full rounded-lg border p-3 text-left transition-all flex items-center justify-between ${
                          selectedProject?.id === project.id
                            ? 'border-accent bg-accent/10 shadow-[0_0_12px_rgba(59,130,246,0.2)]'
                            : 'border-white/5 bg-white/5 hover:bg-white/10 hover:border-white/10'
                        }`}
                      >
                        <div className="truncate pr-4">
                          <div className="font-mono text-[10px] font-bold text-white truncate">{project.name}</div>
                          <div className="font-mono text-[8px] text-muted truncate">{project.scope}</div>
                        </div>
                        {project.rewards && (
                          <span className="font-mono text-[9px] font-bold text-accent px-2 py-0.5 rounded border border-accent/20 bg-accent/5">
                            {project.rewards}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="space-y-6">
              <div>
                <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-white mb-2 flex items-center gap-2">
                  <Icon name="settings" size={14} className="text-accent" /> Scan Preset
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      setScanMode('safe');
                      setSelectedModules(['subdomain_enum', 'url_discovery', 'port_scan', 'httpx']);
                    }}
                    className={`flex flex-col items-start rounded-xl border p-3.5 text-left transition-all ${
                      scanMode === 'safe'
                        ? 'border-accent bg-accent/10 shadow-[0_0_15px_rgba(59,130,246,0.15)] text-white'
                        : 'border-white/5 bg-white/5 text-muted hover:bg-white/10'
                    }`}
                  >
                    <span className="text-xs font-black uppercase tracking-wider text-white">Passive Safe</span>
                    <span className="mt-1 text-[9px] leading-relaxed opacity-60 font-mono">
                      Passive metadata gathering. Low footprint.
                    </span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setScanMode('aggressive');
                      setSelectedModules(['subdomain_enum', 'url_discovery', 'port_scan', 'httpx', 'nuclei']);
                    }}
                    className={`flex flex-col items-start rounded-xl border p-3.5 text-left transition-all ${
                      scanMode === 'aggressive'
                        ? 'border-accent bg-accent/10 shadow-[0_0_15px_rgba(59,130,246,0.15)] text-white'
                        : 'border-white/5 bg-white/5 text-muted hover:bg-white/10'
                    }`}
                  >
                    <span className="text-xs font-black uppercase tracking-wider text-white">Active Vulnerability</span>
                    <span className="mt-1 text-[9px] leading-relaxed opacity-60 font-mono">
                      Intrusive active probe scan sequences.
                    </span>
                  </button>
                </div>
              </div>

              <div className="space-y-3 rounded-xl border border-white/5 bg-black/40 p-4">
                <div className="flex items-center justify-between font-mono text-[9px] uppercase tracking-wider text-muted">
                  <span>Depth: Level {scanDepth}</span>
                  <span>Concurrency: {scanConcurrency} workers</span>
                </div>
                <div className="space-y-2">
                  <input
                    type="range"
                    min={1}
                    max={8}
                    value={scanDepth}
                    onChange={(e) => setScanDepth(Number(e.target.value))}
                    className="cockpit-slider w-full"
                    aria-label="Crawl Depth"
                  />
                  <input
                    type="range"
                    min={1}
                    max={64}
                    value={scanConcurrency}
                    onChange={(e) => setScanConcurrency(Number(e.target.value))}
                    className="cockpit-slider w-full"
                    aria-label="Concurrency"
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="mt-8 border-t border-white/5 pt-6 flex items-center justify-end">
            <button
              type="button"
              onClick={onStartScan}
              disabled={launchingScan || !inputTarget.trim()}
              className="w-full sm:w-auto rounded-lg bg-accent px-8 py-3 text-center text-xs font-black uppercase tracking-[0.2em] text-black shadow-[0_0_20px_rgba(59,130,246,0.3)] transition-all hover:bg-white disabled:opacity-40 disabled:shadow-none font-mono"
            >
              {launchingScan ? 'INITIALIZING OPERATIONS...' : 'ENGAGE PIPELINE ENGINE'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export const CockpitSetupView = memo(CockpitSetupViewBase);
