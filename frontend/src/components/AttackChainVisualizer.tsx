import { memo, useMemo, useState } from 'react';
import { ArrowRight, List, Network, Shield, Target, Zap } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';
import type { AttackChain } from '@/types/api';
import type { CockpitEdge, CockpitNode } from '@/api/cockpit';
import { AttackChainGraph3D } from '@/components/charts';

interface AttackChainVisualizerProps {
  chains: AttackChain[];
  onFindingSelect?: (findingId: string) => void;
}

const severityRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function chainToGraph(chain: AttackChain): { nodes: CockpitNode[]; edges: CockpitEdge[] } {
  const nodes: CockpitNode[] = [];
  const edges: CockpitEdge[] = [];
  const seen = new Set<string>();

  chain.steps.forEach((step, index) => {
    const assetId = `asset:${step.asset_id}`;
    const findingId = `finding:${step.finding_id}`;
    if (!seen.has(assetId)) {
      nodes.push({
        id: assetId,
        type: index === 0 ? 'subdomain' : 'endpoint',
        label: step.asset_id,
        severity: 'info',
        metadata: { health: 0.86, host: step.asset_id },
      });
      seen.add(assetId);
    }
    if (!seen.has(findingId)) {
      nodes.push({
        id: findingId,
        type: 'finding',
        label: step.finding_id,
        severity: step.severity || 'high',
        metadata: { health: 1 - ((severityRank[step.severity] || 3) * 0.14), finding_id: step.finding_id },
      });
      seen.add(findingId);
    }
    edges.push({ source: assetId, target: findingId, label: 'exposes', metadata: { relationship: 'exposes' } });

    const next = chain.steps[index + 1];
    if (next) {
      edges.push({
        source: findingId,
        target: `asset:${next.asset_id}`,
        label: 'pivots_to',
        metadata: { relationship: 'lateral_movement' },
      });
    }
  });

  return { nodes, edges };
}

export const AttackChainVisualizer = memo(function AttackChainVisualizer({
  chains,
  onFindingSelect,
}: AttackChainVisualizerProps) {
  const [viewMode, setViewMode] = useState<'cards' | 'graph'>('graph');
  const [selectedChainId, setSelectedChainId] = useState<string | null>(chains[0]?.id ?? null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  const activeChain = useMemo(
    () => chains.find((chain) => chain.id === selectedChainId) || chains[0],
    [chains, selectedChainId],
  );
  const activeGraph = useMemo(
    () => (activeChain ? chainToGraph(activeChain) : { nodes: [], edges: [] }),
    [activeChain],
  );

  if (chains.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-20 text-muted opacity-40">
        <Shield size={48} strokeWidth={1} />
        <p className="text-xs uppercase tracking-[0.2em]">No Kill-Chains Identified</p>
      </div>
    );
  }

  const handleSelectNode = (id: string) => {
    setSelectedNodeId(id);
    if (id.startsWith('finding:')) {
      onFindingSelect?.(id.replace('finding:', ''));
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3">
        <h4 className="text-[10px] font-black uppercase tracking-[0.3em] text-white/45">Kill-Chain Model</h4>
        <div className="flex rounded border border-white/10 bg-white/5 p-1">
          <button
            type="button"
            aria-label="List view"
            onClick={() => setViewMode('cards')}
            className={`rounded p-1.5 transition-all ${viewMode === 'cards' ? 'bg-cyan-300 text-black' : 'text-muted hover:text-white'}`}
          >
            <List size={14} />
          </button>
          <button
            type="button"
            aria-label="3D graph view"
            onClick={() => setViewMode('graph')}
            className={`rounded p-1.5 transition-all ${viewMode === 'graph' ? 'bg-cyan-300 text-black' : 'text-muted hover:text-white'}`}
          >
            <Network size={14} />
          </button>
        </div>
      </div>

      <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-cyber">
        {chains.map((chain, index) => (
          <button
            key={chain.id}
            type="button"
            onClick={() => setSelectedChainId(chain.id)}
            className={`shrink-0 rounded border px-3 py-2 text-left transition-colors ${
              activeChain?.id === chain.id
                ? 'border-cyan-300/60 bg-cyan-300/10 text-white'
                : 'border-white/10 bg-white/5 text-muted hover:text-white'
            }`}
          >
            <div className="text-[9px] font-black uppercase tracking-widest">Path {index + 1}</div>
            <div className="mt-1 text-[10px] font-mono">{Math.round(chain.confidence * 100)}% confidence</div>
          </button>
        ))}
      </div>

      {activeChain && (
        <motion.div
          key={activeChain.id}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="overflow-hidden rounded border border-white/10 bg-black/45"
        >
          <div className="flex items-start justify-between gap-4 border-b border-white/10 p-4">
            <div>
              <div className="mb-2 inline-flex items-center gap-2 rounded bg-red-500/10 px-2 py-1 text-[9px] font-black uppercase tracking-widest text-red-300">
                <Target size={12} />
                Critical Attack Path
              </div>
              <h3 className="text-sm font-bold leading-snug text-text">{activeChain.description}</h3>
            </div>
            <div className="text-right">
              <div className="text-xl font-black text-white">{Math.round(activeChain.confidence * 100)}%</div>
              <div className="text-[9px] font-bold uppercase tracking-widest text-muted">Confidence</div>
            </div>
          </div>

          <AnimatePresence mode="wait">
            {viewMode === 'cards' ? (
              <motion.div
                key="cards"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex items-center gap-4 overflow-x-auto p-4 scrollbar-cyber"
              >
                {activeChain.steps.map((step, index) => (
                  <div key={`${step.finding_id}-${index}`} className="flex shrink-0 items-center gap-4">
                    <button
                      type="button"
                      onClick={() => onFindingSelect?.(step.finding_id)}
                      className="flex flex-col items-center gap-2 rounded border border-white/10 bg-white/5 p-3 hover:border-cyan-300/50"
                    >
                      <div className="flex h-11 w-11 items-center justify-center rounded border border-red-400/30 bg-red-500/10 text-red-300">
                        <Zap size={18} />
                      </div>
                      <div className="max-w-[110px] truncate text-[9px] font-mono text-muted">{step.asset_id}</div>
                    </button>
                    {index < activeChain.steps.length - 1 && (
                      <div className="flex flex-col items-center gap-1 text-cyan-200">
                        <ArrowRight size={16} />
                        <span className="text-[8px] font-black uppercase tracking-widest">Pivot</span>
                      </div>
                    )}
                  </div>
                ))}
              </motion.div>
            ) : (
              <motion.div
                key="graph"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="h-[320px]"
              >
                <AttackChainGraph3D
                  nodes={activeGraph.nodes}
                  edges={activeGraph.edges}
                  selectedNodeId={selectedNodeId}
                  hoveredNodeId={hoveredNodeId}
                  onSelectNode={handleSelectNode}
                  onHoverNode={setHoveredNodeId}
                  className="h-full w-full"
                />
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      )}
    </div>
  );
});
