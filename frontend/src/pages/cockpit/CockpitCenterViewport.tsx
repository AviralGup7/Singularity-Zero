import { memo, lazy, Suspense, useCallback } from 'react';
import { Icon } from '@/components/ui/Icon';
import { AttackChainVisualizer } from '@/components/AttackChainVisualizer';
import type { CockpitEdge, CockpitNode } from '@/api/cockpit';
import type { AttackChain } from '@/types/api';

const AttackChainGraph3D = lazy(() =>
  import('@/components/charts/AttackChainGraph3D').then((m) => ({ default: m.AttackChainGraph3D }))
);

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-critical border-critical/30 bg-critical/5',
  high: 'text-high border-high/30 bg-high/5',
  medium: 'text-medium border-medium/30 bg-medium/5',
  low: 'text-low border-low/30 bg-low/5',
  info: 'text-info border-info/30 bg-info/5',
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
  const handleHoverNode = useCallback((id: string | null) => onHoverNode(id), [onHoverNode]);

  return (
    <div className="flex-1 flex flex-col items-stretch bg-bg relative overflow-hidden">
      <div className="flex-shrink-0 flex items-center justify-between border-b border-line-muted px-6 py-3 bg-surface/40 z-10">
        <div className="flex gap-2" role="tablist" aria-label="Viewport mode">
          {(['3d', '2d', 'chains'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveCenterTab(tab)}
              role="tab"
              aria-selected={activeCenterTab === tab}
              className={`px-3 py-1.5 rounded font-mono text-[10px] font-bold uppercase tracking-wider transition-all border ${
                activeCenterTab === tab
                  ? 'border-accent/40 bg-accent/10 text-text-primary shadow-glow-accent-sm'
                  : 'border-transparent text-text-secondary hover:text-text-primary'
              }`}
            >
              {tab === '3d' && '[ 3D Threat Topology ]'}
              {tab === '2d' && '[ 2D Node Grid ]'}
              {tab === 'chains' && `[ Attack Kill-Chains (${chains.length}) ]`}
            </button>
          ))}
        </div>
        {activeCenterTab === '3d' && (
          <div className="text-[10px] font-mono text-text-secondary uppercase tracking-widest flex items-center gap-1.5">
            <span className="pulse-dot" /> Dynamic 3D Renderer Active
          </div>
        )}
      </div>

      <div className="flex-1 relative overflow-hidden">
        {loading ? (
          <div className="flex h-full items-center justify-center animate-pulse font-mono text-xs uppercase tracking-widest text-accent/40">
            Syncing Cluster Graph...
          </div>
        ) : nodes.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-text-tertiary/50 p-12">
            <Icon name="alertTriangle" size={48} className="text-text-tertiary/30" />
            <p className="mt-4 uppercase tracking-[0.2em] font-mono text-xs">No active telemetry nodes mapped</p>
            <p className="mt-1 font-mono text-[10px] text-text-tertiary/40">Try adjusting your scan settings or preset mode.</p>
          </div>
        ) : activeCenterTab === '3d' ? (
          <Suspense
            fallback={
              <div className="flex h-full items-center justify-center font-mono text-[10px] uppercase tracking-widest text-accent/40 animate-pulse">
                Loading 3D renderer...
              </div>
            }
          >
            <AttackChainGraph3D
              nodes={nodes}
              edges={edges}
              selectedNodeId={selectedNodeId}
              hoveredNodeId={hoveredNodeId}
              onSelectNode={onSelectNode}
              onHoverNode={handleHoverNode}
              className="h-full w-full"
            />
          </Suspense>
        ) : activeCenterTab === '2d' ? (
          <div className="absolute inset-0 overflow-y-auto p-6 scrollbar-cyber space-y-2">
            {nodes.map((node) => {
              const healthVal = typeof node.metadata?.health === 'number' ? Math.round(node.metadata.health * 100) : 82;
              const isFocused = selectedNodeId === node.id || hoveredNodeId === node.id;
              return (
                <div
                  key={node.id}
                  onClick={() => onSelectNode(node.id)}
                  onKeyDown={(e) => { if (e.key === 'Enter') onSelectNode(node.id); }}
                  role="button"
                  tabIndex={0}
                  className={`flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 rounded-xl border transition-all cursor-pointer ${
                    isFocused
                      ? 'border-accent bg-accent/10 shadow-glow-accent-sm'
                      : 'border-line-muted bg-surface/40 hover:border-line hover:bg-surface/60'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`rounded-lg border px-2.5 py-1 text-[9px] font-bold uppercase tracking-wider ${SEVERITY_COLORS[node.severity]}`}>
                      {node.severity}
                    </div>
                    <div>
                      <div className="font-mono text-xs font-bold text-text-primary">{node.label}</div>
                    <div className="font-mono text-[9px] text-text-secondary truncate max-w-sm" title={metadataText(node.metadata, 'url') || node.id}>
                      {metadataText(node.metadata, 'url') || node.id}
                    </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 mt-2 sm:mt-0 font-mono text-[10px]">
                    <div className="text-right">
                      <div className="text-[9px] uppercase text-text-secondary">Type</div>
                      <div className="font-bold text-text-primary uppercase">{node.type}</div>
                    </div>
                    <div className="text-right min-w-24">
                      <div className="text-[9px] uppercase text-text-secondary">Node Health</div>
                      <div className="font-bold text-ok tabular-nums">{healthVal}%</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="absolute inset-0 overflow-y-auto p-6 scrollbar-cyber">
            <AttackChainVisualizer
              chains={chains}
              onFindingSelect={onFindingSelect}
            />
          </div>
        )}
      </div>
    </div>
  );
}

export const CockpitCenterViewport = memo(CockpitCenterViewportBase);
