import { memo, useEffect, useRef, useState } from 'react';
import { Shield, ArrowRight, Zap, Target, AlertTriangle, Network, List } from 'lucide-react';
import type { AttackChain } from '@/types/api';
import { motion, AnimatePresence } from 'framer-motion';
import * as d3Force from 'd3-force';

// ─────────────────────────────────────────────────────────────────────────────
// D3 Force Graph Component (Optimized for standalone d3-force)
// ─────────────────────────────────────────────────────────────────────────────

interface GraphNode extends d3Force.SimulationNodeDatum {
  id: string;
  label: string;
  severity: string;
  x?: number;
  y?: number;
}

interface GraphLink extends d3Force.SimulationLinkDatum<GraphNode> {
  source: string | GraphNode;
  target: string | GraphNode;
}

const AttackGraph = memo(function AttackGraph({ chain }: { chain: AttackChain }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [links, setLinks] = useState<GraphLink[]>([]);

  useEffect(() => {
    const width = 400;
    const height = 200;

    const initialNodes: GraphNode[] = chain.steps.map((step) => ({
      id: step.finding_id,
      label: step.asset_id,
      severity: step.severity,
    }));

    const initialLinks: GraphLink[] = [];
    let prevNode: GraphNode | null = null;
    for (const node of initialNodes) {
      if (prevNode) {
        initialLinks.push({ source: prevNode.id, target: node.id });
      }
      prevNode = node;
    }

    const simulation = d3Force.forceSimulation<GraphNode>(initialNodes)
      .force("link", d3Force.forceLink<GraphNode, GraphLink>(initialLinks).id(d => d.id).distance(80))
      .force("charge", d3Force.forceManyBody().strength(-200))
      .force("center", d3Force.forceCenter(width / 2, height / 2))
      .force("x", d3Force.forceX(width / 2).strength(0.1))
      .force("y", d3Force.forceY(height / 2).strength(0.1));

    simulation.on("tick", () => {
      setNodes([...initialNodes]);
      setLinks([...initialLinks]);
    });

    return () => { simulation.stop(); };
  }, [chain]);

  return (
    <div ref={containerRef} className="bg-black/40 rounded-xl border border-white/5 overflow-hidden h-[200px] relative">
      <svg width="100%" height="100%" viewBox="0 0 400 200" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker
            id={`arrow-${chain.id}`}
            viewBox="0 -5 10 10"
            refX={20}
            refY={0}
            markerWidth={6}
            markerHeight={6}
            orient="auto"
          >
            <path d="M0,-5L10,0L0,5" fill="#444" />
          </marker>
        </defs>
        
        {links.map((link, i) => {
          const s = link.source as GraphNode;
          const t = link.target as GraphNode;
          return (
            <line
              key={i}
              x1={s.x}
              y1={s.y}
              x2={t.x}
              y2={t.y}
              stroke="#333"
              strokeWidth={2}
              markerEnd={`url(#arrow-${chain.id})`}
            />
          );
        })}

        {nodes.map((node) => (
          <g key={node.id} transform={`translate(${node.x || 0},${node.y || 0})`}>
            <motion.circle
              r={12}
              animate={{
                r: [12, 13, 12],
                strokeWidth: [2, 3, 2]
              }}
              transition={{
                duration: 2,
                repeat: Infinity,
                ease: "easeInOut"
              }}
              fill={node.severity === 'critical' ? '#ff0055' : '#ef4444'}
              stroke="#000"
              strokeWidth={2}
            />
            <text
              y={25}
              textAnchor="middle"
              fill="#94a3b8"
              fontSize="8px"
              fontFamily="monospace"
            >
              {node.label}
            </text>
          </g>
        ))}
      </svg>
      <div className="absolute bottom-2 right-2 text-[8px] font-mono text-muted uppercase tracking-widest opacity-50">
        React-Rendered Force Engine Active
      </div>
    </div>
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// Primary Component
// ─────────────────────────────────────────────────────────────────────────────

export const AttackChainVisualizer = memo(function AttackChainVisualizer({ 
  chains 
}: { 
  chains: AttackChain[] 
}) {
  const [viewMode, setViewMode] = useState<'cards' | 'graph'>('cards');

  if (chains.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-muted opacity-30 gap-4">
        <Shield size={48} strokeWidth={1} />
        <p className="text-xs uppercase tracking-[0.2em]">No Kill-Chains Identified</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-[10px] font-black text-white/40 uppercase tracking-[0.3em]">Neural Correlation Results</h4>
        <div className="flex bg-white/5 rounded-lg p-1 border border-white/5">
          <button 
            onClick={() => setViewMode('cards')}
            className={`p-1.5 rounded-md transition-all ${viewMode === 'cards' ? 'bg-accent text-black shadow-lg' : 'text-muted hover:text-white'}`}
          >
            <List size={14} />
          </button>
          <button 
            onClick={() => setViewMode('graph')}
            className={`p-1.5 rounded-md transition-all ${viewMode === 'graph' ? 'bg-accent text-black shadow-lg' : 'text-muted hover:text-white'}`}
          >
            <Network size={14} />
          </button>
        </div>
      </div>

      <div className="space-y-8">
        {chains.map((chain, idx) => (
          <motion.div 
            key={chain.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.1 }}
            className="glass-panel p-6 rounded-2xl border-l-4 border-l-bad relative overflow-hidden"
          >
            <div className="absolute top-0 right-0 p-4 opacity-10">
               <Target size={120} />
            </div>

            <div className="flex items-center justify-between mb-6 relative z-10">
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-black text-bad uppercase tracking-widest px-2 py-0.5 bg-bad/10 rounded inline-block">
                    Critical Attack Path
                  </span>
                  {chain.confidence > 0.9 && (
                    <span className="flex items-center gap-1 text-[9px] font-black text-accent bg-accent/10 px-2 py-0.5 rounded animate-pulse">
                      <div className="w-1 h-1 rounded-full bg-accent" /> LIVE
                    </span>
                  )}
                </div>
                <h3 className="text-lg font-bold text-text uppercase tracking-tighter">{chain.description}</h3>
              </div>
              <div className="text-right">
                 <div className="text-2xl font-black text-white">{Math.round(chain.confidence * 100)}%</div>
                 <div className="text-[9px] text-muted uppercase font-bold tracking-widest">Confidence</div>
              </div>
            </div>

            <AnimatePresence mode="wait">
              {viewMode === 'cards' ? (
                <motion.div 
                  key="cards"
                  initial={{ opacity: 0, scale: 0.98 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.98 }}
                  className="flex items-center gap-4 overflow-x-auto pb-4 scrollbar-cyber relative z-10"
                >
                  {chain.steps.map((step, sIdx) => (
                    <div key={sIdx} className="flex items-center gap-4 shrink-0">
                      <div className="flex flex-col items-center gap-2">
                         <div className={`w-12 h-12 rounded-xl border flex items-center justify-center ${
                           step.severity === 'critical' ? 'bg-bad/10 border-bad/30 text-bad shadow-[0_0_15px_rgba(255,0,85,0.2)]' : 'bg-high/10 border-high/30 text-high'
                         }`}>
                            <Zap size={20} />
                         </div>
                         <div className="text-[9px] font-mono text-muted truncate max-w-[80px]">{step.asset_id}</div>
                      </div>
                      
                      {sIdx < chain.steps.length - 1 && (
                        <div className="flex flex-col items-center gap-1">
                          <ArrowRight size={16} className="text-muted" />
                          <span className="text-[8px] font-black text-accent uppercase tracking-tighter">Pivot</span>
                        </div>
                      )}
                    </div>
                  ))}
                </motion.div>
              ) : (
                <motion.div
                  key="graph"
                  initial={{ opacity: 0, scale: 0.98 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.98 }}
                >
                  <AttackGraph chain={chain} />
                </motion.div>
              )}
            </AnimatePresence>

            <div className="mt-4 p-3 bg-black/40 rounded-lg border border-white/5 flex items-center gap-3">
               <AlertTriangle size={14} className="text-warn" />
               <p className="text-[10px] text-muted font-mono leading-relaxed">
                 Tactical Warning: This path utilizes an authenticated logical breach on {chain.steps[0].asset_id} to gain deeper access.
               </p>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
});
