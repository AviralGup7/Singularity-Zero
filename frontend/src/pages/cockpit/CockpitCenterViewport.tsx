import { lazy, Suspense, memo } from 'react';
import { Icon } from '@/components/ui/Icon';
import { AttackChainVisualizer } from '@/components/AttackChainVisualizer';
import type { CockpitEdge, CockpitNode } from '@/api/cockpit';
import type { AttackChain } from '@/types/api';

const AttackChainGraph3D = lazy(() =>
  import('@/components/charts/AttackChainGraph3D').then((m) => ({ default: m.AttackChainGraph3D }))
);

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500 border-red-500/30 bg-red-500/5',
  high: 'text-orange-500 border-orange-500/30 bg-orange-500/5',
  medium: 'text-amber-500 border-amber-500/30 bg-amber-500/5',
  low: 'text-blue-500 border-blue-500/30 bg-blue-500/5',
  info: 'text-slate-400 border-slate-400/30 bg-slate-400/5',
};

function metadataText(metadata: CockpitNode['metadata'], key: string): string {
  const value = metadata ? Reflect.get(metadata, key) : undefined;
  if (typeof value === 'string') return value;
  if (value == null) return '';
  return String(value);
}

interface CockpitCenterViewportProps {
  activeCenterTab: '3d' | '2d' | 'chains';
  setActiveCenterTab: (tab: '3d' | '2d' | 'chains') => void;
  nodes: CockpitNode[];
  edges: CockpitEdge[];
  chains: AttackChain[];
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  onSelectNode: (id: string) => void;
  onHoverNode: (id: string | null) => void;
  loading: boolean;
  onFindingSelect: (findingId: string) => void;
}

function CockpitCenterViewportBase({
  activeCenterTab,
  setActiveCenterTab,
  nodes,
  edges,
  chains,
  selectedNodeId,
  hoveredNodeId,
  onSelectNode,
  onHoverNode,
  loading,
  onFindingSelect,
}: CockpitCenterViewportProps) {
  return (
    <div className="flex-1 flex flex-col items-stretch bg-[#020305] relative overflow-hidden">
      {/* Center View Switched Controls */}
      <div className="flex-shrink-0 flex items-center justify-between border-b border-white/5 px-6 py-3 bg-[#080a0e]/40 z-10">
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setActiveCenterTab('3d')}
            className={`px-3 py-1.5 rounded font-mono text-[10px] font-bold uppercase tracking-wider transition-all border ${
              activeCenterTab === '3d'
                ? 'border-accent/40 bg-accent/10 text-white shadow-[0_0_10px_rgba(59,130,246,0.15)]'
                : 'border-transparent text-muted hover:text-white'
            }`}
          >
            [ 3D Threat Topology ]
          </button>
          <button
            type="button"
            onClick={() => setActiveCenterTab('2d')}
            className={`px-3 py-1.5 rounded font-mono text-[10px] font-bold uppercase tracking-wider transition-all border ${
              activeCenterTab === '2d'
                ? 'border-accent/40 bg-accent/10 text-white shadow-[0_0_10px_rgba(59,130,246,0.15)]'
                : 'border-transparent text-muted hover:text-white'
            }`}
          >
            [ 2D Node Grid ]
          </button>
          <button
            type="button"
            onClick={() => setActiveCenterTab('chains')}
            className={`px-3 py-1.5 rounded font-mono text-[10px] font-bold uppercase tracking-wider transition-all border ${
              activeCenterTab === 'chains'
                ? 'border-accent/40 bg-accent/10 text-white shadow-[0_0_10px_rgba(59,130,246,0.15)]'
                : 'border-transparent text-muted hover:text-white'
            }`}
          >
            [ Attack Kill-Chains ({chains.length}) ]
          </button>
        </div>
        {activeCenterTab === '3d' && (
          <div className="text-[10px] font-mono text-muted uppercase tracking-widest flex items-center gap-1.5">
            <span className="pulse-dot" /> Dynamic 3D Renderer Active
          </div>
        )}
      </div>

      {/* Actual View render */}
      <div className="flex-1 relative overflow-hidden">
        {loading ? (
          <div className="flex h-full items-center justify-center animate-pulse font-mono text-xs uppercase tracking-widest text-accent/40">
            Syncing Cluster Graph...
          </div>
        ) : nodes.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-muted/50 p-12">
            <Icon name="alertTriangle" size={48} className="text-muted/30" />
            <p className="mt-4 uppercase tracking-[0.2em] font-mono text-xs">No active telemetry nodes mapped</p>
            <p className="mt-1 font-mono text-[10px] text-muted/40">Try adjusting your scan settings or preset mode.</p>
          </div>
        ) : activeCenterTab === '3d' ? (
          <Suspense
            fallback={
              <div className="flex h-full items-center justify-center animate-pulse font-mono text-xs uppercase tracking-widest text-accent/40">
                Loading 3D Visualizer Engine...
              </div>
            }
          >
            <AttackChainGraph3D
              nodes={nodes}
              edges={edges}
              selectedNodeId={selectedNodeId}
              hoveredNodeId={hoveredNodeId}
              onSelectNode={onSelectNode}
              onHoverNode={onHoverNode}
              className="h-full w-full"
            />
          </Suspense>
        ) : activeCenterTab === '2d' ? (
          <div className="absolute inset-0 overflow-y-auto p-6 scrollbar-cyber space-y-2">
            {nodes.map((node) => {
              const healthVal =
                typeof node.metadata?.health === 'number' ? Math.round(node.metadata.health * 100) : 82;
              const isFocused = selectedNodeId === node.id || hoveredNodeId === node.id;
              return (
                <div
                  key={node.id}
                  onClick={() => onSelectNode(node.id)}
                  className={`flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 rounded-xl border transition-all cursor-pointer ${
                    isFocused
                      ? 'border-accent bg-accent/10 shadow-[0_0_15px_rgba(59,130,246,0.12)]'
                      : 'border-white/5 bg-[#0a0d13]/40 hover:border-white/10 hover:bg-[#0a0d13]/60'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`rounded-lg border px-2.5 py-1 text-[9px] font-bold uppercase tracking-wider ${
                        SEVERITY_COLORS[node.severity || 'info']
                      }`}
                    >
                      {node.severity}
                    </div>
                    <div>
                      <div className="font-mono text-xs font-bold text-white">{node.label}</div>
                      <div className="font-mono text-[9px] text-muted truncate max-w-sm">
                        {metadataText(node.metadata, 'url') || node.id}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 mt-2 sm:mt-0 font-mono text-[10px]">
                    <div className="text-right">
                      <div className="text-[9px] uppercase text-muted">Type</div>
                      <div className="font-bold text-white uppercase">{node.type}</div>
                    </div>
                    <div className="text-right min-w-24">
                      <div className="text-[9px] uppercase text-muted">Node Health</div>
                      <div className="font-bold text-emerald-400">{healthVal}%</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="absolute inset-0 overflow-y-auto p-6 scrollbar-cyber">
            <AttackChainVisualizer chains={chains} onFindingSelect={onFindingSelect} />
          </div>
        )}
      </div>
    </div>
  );
}

export const CockpitCenterViewport = memo(CockpitCenterViewportBase);
