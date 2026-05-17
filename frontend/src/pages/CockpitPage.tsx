import { useState, useEffect, useMemo, Suspense, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { OrbitControls, PerspectiveCamera, Stars } from '@react-three/drei';
import { EffectComposer, Bloom, Vignette, ChromaticAberration } from '@react-three/postprocessing';
import * as THREE from 'three';
import { Icon } from '@/components/Icon';
import { motion, AnimatePresence } from 'framer-motion';
import { cockpitApi } from '@/api/cockpit';
import type { CockpitNode, CockpitEdge, ForensicExchange } from '@/api/cockpit';
import type { AttackChain } from '@/types/api';
import { getNotes, createNote } from '@/api/notes';
import type { Note } from '@/api/notes';
import { apiClient } from '@/api/client';
import { AttackChainVisualizer } from '@/components/AttackChainVisualizer';
import { useToast } from '@/hooks/useToast';

// ─────────────────────────────────────────────────────────────────────────────
// High-Performance Instanced Components
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff0055',
  high: '#ef4444',
  medium: '#f59e0b',
  low: '#3b82f6',
  info: '#94a3b8',
};

   
function metadataText(metadata: CockpitNode['metadata'], key: string): string {
  const value = metadata?.[key];
  if (typeof value === 'string') return value;
  if (value == null) return '';
  return String(value);
}

function InstancedNodes({ 
  nodes, 
  selectedId, 
  onSelect,
  onHover
}: { 
  nodes: CockpitNode[]; 
  selectedId: string | null;
  onSelect: (id: string) => void;
  onHover: (id: string | null) => void;
}) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const meshRef = useRef<any>(null);
  const { raycaster, camera, mouse } = useThree();

  const { matrices, colors } = useMemo(() => {
    const tempMatrix = new THREE.Object3D();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tempColor = new (THREE as any).Color();
    const m = new Float32Array(nodes.length * 16);
    const c = new Float32Array(nodes.length * 3);

    nodes.forEach((node, i) => {
   
      const [x, y, z] = node.position || [0, 0, 0];
      tempMatrix.position.set(x, y, z);
      const scale = node.id === selectedId ? 1.4 : 0.7;
      tempMatrix.scale.set(scale, scale, scale);
      tempMatrix.updateMatrix();
      tempMatrix.matrix.toArray(m, i * 16);

   
      tempColor.set(SEVERITY_COLORS[node.severity] || '#ffffff');
      tempColor.toArray(c, i * 3);
    });
    return { matrices: m, colors: c };
   
  }, [nodes, selectedId]);

  useEffect(() => {
    if (meshRef.current) {
      meshRef.current.instanceMatrix.set(matrices);
      meshRef.current.instanceMatrix.needsUpdate = true;
      if (meshRef.current.instanceColor) {
        meshRef.current.instanceColor.set(colors);
        meshRef.current.instanceColor.needsUpdate = true;
      }
    }
   
  }, [matrices, colors]);

  useFrame(() => {
    if (!meshRef.current) return;
    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObject(meshRef.current);
    if (intersects.length > 0) {
   
      const instanceId = intersects[0].instanceId;
      if (instanceId !== undefined) onHover(nodes[instanceId].id);
    } else {
      onHover(null);
    }
  });

  return (
    // @ts-ignore
    <instancedMesh 
      ref={meshRef} 
   
      args={[null!, null!, nodes.length]}
       
   
      onClick={(e: any) => e.instanceId !== undefined && onSelect(nodes[e.instanceId].id)}
    >
      <sphereGeometry args={[0.5, 16, 16]} />
      <meshStandardMaterial 
        emissiveIntensity={2} 
        toneMapped={false} 
        metalness={0.9}
        roughness={0.1}
      />
      {/* @ts-ignore */}
    </instancedMesh>
  );
}

   
function OptimizedEdges({ edges, nodes }: { edges: CockpitEdge[]; nodes: CockpitNode[] }) {
  const linePoints = useMemo(() => {
   
    const points: number[] = [];
    edges.forEach(edge => {
      const source = nodes.find(n => n.id === edge.source);
      const target = nodes.find(n => n.id === edge.target);
      if (source?.position && target?.position) {
        points.push(...source.position, ...target.position);
      }
    });
    return new Float32Array(points);
   
  }, [edges, nodes]);

  if (linePoints.length === 0) return null;

  return (
    // @ts-ignore
    <lineSegments>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={linePoints.length / 3}
          array={linePoints}
          itemSize={3}
   
          args={[linePoints, 3]}
        />
      </bufferGeometry>
      <lineBasicMaterial color="#1e293b" transparent opacity={0.3} />
    {/* @ts-ignore */}
    </lineSegments>
  );
}

   
function Scene({ nodes, edges, selectedNode, onSelect, onHover }: { nodes: CockpitNode[]; edges: CockpitEdge[]; selectedNode: string | null; onSelect: (id: string) => void; onHover: (id: string | null) => void }) {
  return (
    <>
      {/* @ts-ignore */}
      <color attach="background" args={['#020204']} />
      {/* @ts-ignore */}
      <fog attach="fog" args={['#020204', 10, 80]} />
      
      <ambientLight intensity={0.2} />
      <pointLight position={[20, 20, 20]} intensity={1.5} color="var(--color-accent)" />
      <Stars radius={100} depth={50} count={3000} factor={4} saturation={0} fade speed={1} />
      
      <InstancedNodes nodes={nodes} selectedId={selectedNode} onSelect={onSelect} onHover={onHover} />
      <OptimizedEdges edges={edges} nodes={nodes} />
      
      <PerspectiveCamera makeDefault position={[0, 0, 35]} />
      <OrbitControls makeDefault enableDamping dampingFactor={0.05} minDistance={5} maxDistance={100} />
      
      <EffectComposer>
        <Bloom luminanceThreshold={1} mipmapBlur intensity={1.2} radius={0.3} />
        {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
        <ChromaticAberration offset={new (THREE as any).Vector2(0.001, 0.001)} />
        <Vignette eskil={false} offset={0.1} darkness={1.1} />
      </EffectComposer>
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// UI Sub-components
// ─────────────────────────────────────────────────────────────────────────────

function ForensicExchangeItem({ exchange, onOpen }: { exchange: ForensicExchange; onOpen: (id: string) => void }) {
  const responseStatus = exchange.response_status || exchange.response?.status;
  return (
    <button 
      className="w-full text-left p-3 border border-line rounded-lg bg-black/20 hover:bg-black/40 cursor-pointer transition-colors focus:outline-none focus:border-accent/50" 
      onClick={() => onOpen(exchange.exchange_id)}
    >
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] font-mono text-muted">{exchange.exchange_id}</span>
        <span className="text-[10px] text-muted">{new Date(exchange.timestamp).toLocaleTimeString()}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className={`text-[10px] font-bold px-1 rounded ${responseStatus && responseStatus < 300 ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400'}`}>{responseStatus}</span>
        <span className="text-xs font-bold text-text truncate">{exchange.method} {exchange.url}</span>
      </div>
    </button>
  );
}

function ForensicExchangeDetail({ exchange, onBack }: { exchange: ForensicExchange; onBack: () => void }) {
  return (
    <div className="flex flex-col h-full bg-background">
      <div className="p-4 border-b border-line flex items-center gap-3 bg-black/20">
        <button onClick={onBack} className="text-muted hover:text-text"><Icon name="arrowLeft" size={18} /></button>
        <div>
          <h4 className="font-bold text-sm text-text">Exchange Details</h4>
          <div className="text-[10px] text-muted font-mono">{exchange.exchange_id}</div>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        <section>
          <div className="flex items-center justify-between mb-2">
            <h5 className="text-[10px] font-bold text-muted uppercase">Request</h5>
            <span className="text-[10px] text-muted">{exchange.method}</span>
          </div>
          <div className="p-3 rounded bg-black/40 border border-line font-mono text-[10px] break-all mb-2">{exchange.url}</div>
          <div className="space-y-1">
            {Object.entries(exchange.request?.headers || {}).map(([k, v]) => (
   
              <div key={k} className="flex gap-2 text-[10px]"><span className="text-muted font-bold min-w-[80px]">{k}:</span><span className="text-text break-all">{v}</span></div>
            ))}
          </div>
        </section>
        <section>
          <div className="flex items-center justify-between mb-2">
            <h5 className="text-[10px] font-bold text-muted uppercase">Response</h5>
            <span className={`text-[10px] font-bold ${exchange.response?.status < 400 ? 'text-green-400' : 'text-red-400'}`}>STATUS {exchange.response?.status}</span>
          </div>
          {exchange.response?.body_snippet && (
            <div className="mt-3">
              <pre className="p-2 bg-black/60 rounded text-[10px] overflow-x-auto text-text whitespace-pre-wrap">{exchange.response.body_snippet}</pre>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Component
// ─────────────────────────────────────────────────────────────────────────────

export function CockpitPage() {
  const toast = useToast();
   
  const [searchParams] = useSearchParams();
  const target = searchParams.get('target') || '';
  const run = searchParams.get('run') || undefined;
  const jobId = searchParams.get('job_id') || undefined;

   
  const [nodes, setNodes] = useState<CockpitNode[]>([]);
   
  const [edges, setEdges] = useState<CockpitEdge[]>([]);
   
  const [chains, setChains] = useState<AttackChain[]>([]);
   
  const [loading, setLoading] = useState(true);
   
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
   
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
   
  const [sidebarOpen, setSidebarOpen] = useState(false);
   
  const [sidebarTab, setSidebarTab] = useState<'intel' | 'chains' | 'forensics'>('intel');
   
  const [notes, setNotes] = useState<Note[]>([]);
   
  const [exchanges, setExchanges] = useState<ForensicExchange[]>([]);
   
  const [selectedExchange, setSelectedExchange] = useState<ForensicExchange | null>(null);
   
  const [probing, setProbing] = useState(false);
   
  const [newNote, setNewNote] = useState('');

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        setLoading(true);
   
        const [graphRes, chainsRes] = await Promise.all([
           cockpitApi.getGraph(target, run, jobId),
   
           apiClient.get<AttackChain[]>('/api/cockpit/attack-chains', { params: { target } }).catch(() => ({ data: [] }))
        ]);
        
        const { data } = graphRes;
        setChains(chainsRes.data || []);
        
        // Optimized Sphere Layout
        const positionedNodes = data.nodes.map((n, i) => {
          const phi = Math.acos(-1 + (2 * i) / data.nodes.length);
          const theta = Math.sqrt(data.nodes.length * Math.PI) * phi;
          const radius = Math.sqrt(data.nodes.length) * 1.5;
          return {
            ...n,
            position: [
              radius * Math.cos(theta) * Math.sin(phi),
              radius * Math.sin(theta) * Math.sin(phi),
              radius * Math.cos(phi)
   
            ] as [number, number, number]
          };
        });
        
        setNodes(positionedNodes);
        setEdges(data.edges);
      } catch (e) {
        console.error('Failed to fetch cockpit intelligence', e);
      } finally {
        setLoading(false);
      }
    };
    if (target) fetchGraph();
   
  }, [target, run, jobId]);

  useEffect(() => {
    if (target && sidebarOpen) {
      getNotes(target).then(res => setNotes(res.notes)).catch(() => {});
      cockpitApi.listExchanges(target).then(res => setExchanges(res.data.exchanges)).catch(() => {});
    }
   
  }, [target, sidebarOpen]);

   
  const selectedNode = useMemo(() => nodes.find(n => n.id === selectedNodeId), [nodes, selectedNodeId]);
   
  const hoveredNode = useMemo(() => nodes.find(n => n.id === hoveredNodeId), [nodes, hoveredNodeId]);
  const selectedNodeUrl = selectedNode ? metadataText(selectedNode.metadata, 'url') : '';

  const handleOpenForensic = async (id: string) => {
    try {
      const { data } = await cockpitApi.getForensicExchange(target, id);
      setSelectedExchange(data);
    } catch {
      toast.error('Failed to open forensic exchange');
    }
  };

  const handleSelectNode = (id: string) => {
    setSelectedNodeId(id);
    setSelectedExchange(null);
    setSidebarOpen(true);
    setSidebarTab('intel');
  };

  const handleTriggerProbe = async () => {
    if (!selectedNodeUrl) return;
    try {
      setProbing(true);
      await cockpitApi.triggerProbe(target, selectedNodeUrl);
      toast.success('Forensic probe launched');
    } catch {
      toast.error('Probe sequence failed');
    } finally { setProbing(false); }
  };

  const handleAddNote = async () => {
    if (!newNote.trim() || !selectedNode) return;
    try {
      await createNote(target, {
        finding_id: selectedNode.id.replace('finding:', ''),
        note: newNote,
        graph_node_id: selectedNode.id,
        author: 'analyst'
      });
      setNewNote('');
      getNotes(target).then(res => setNotes(res.notes));
    } catch {
      toast.error('Failed to add note');
    }
  };

  return (
   
    <div className="flex h-full w-full bg-[#020204] overflow-hidden relative">
      <div className="flex-1 relative">
        <div className="absolute top-8 left-8 z-10 pointer-events-none">
          <h2 className="text-2xl font-black text-text tracking-tighter uppercase mb-1">Security Cockpit</h2>
          <div className="flex items-center gap-2 text-accent/60 text-xs font-mono uppercase tracking-widest">
            <Icon name="target" size={12} />
            {target || 'Grid Standby'}
          </div>
        </div>

        {/* Floating HUD for Hovered Node */}
        <AnimatePresence>
          {hoveredNode && !sidebarOpen && (
            <motion.div 
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
              className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none z-30"
            >
              <div className="bg-black/80 border border-accent/50 backdrop-blur-xl p-4 rounded-lg shadow-[0_0_30px_rgba(0,255,65,0.2)]">
                <div className="text-[10px] text-accent font-bold uppercase mb-1 tracking-widest">{hoveredNode.severity}</div>
                <div className="text-sm font-bold text-text mb-1">{hoveredNode.label}</div>
                <div className="text-[10px] text-muted font-mono truncate max-w-xs">{metadataText(hoveredNode.metadata, 'url')}</div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {loading ? (
          <div className="flex items-center justify-center h-full text-accent/40 font-mono text-xs uppercase tracking-widest animate-pulse">
            Establishing 3D Neural Link...
          </div>
        ) : nodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-muted opacity-20">
            <Icon name="alertTriangle" size={64} />
            <p className="uppercase tracking-[0.3em] mt-4">No Data Points Detected</p>
          </div>
        ) : (
          <Suspense fallback={null}>
            <Canvas shadows dpr={[1, 2]}>
              <Scene
                nodes={nodes}
                edges={edges}
                selectedNode={selectedNodeId}
                onSelect={handleSelectNode}
                onHover={setHoveredNodeId}
              />
            </Canvas>
          </Suspense>
        )}

        <div className="absolute bottom-8 left-8 flex gap-6 z-10">
          <div className="flex items-center gap-4 bg-black/60 px-4 py-2 rounded border border-white/5 backdrop-blur-md text-[9px] text-muted font-mono uppercase tracking-widest">
            <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-[#ff0055]" /> Critical</div>
            <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-[#ef4444]" /> High</div>
            <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-[#f59e0b]" /> Med</div>
          </div>
          <div className="text-[9px] text-accent/40 self-center bg-black/40 px-4 py-2 rounded border border-white/5 backdrop-blur-md font-mono tracking-widest">
            NODES: {nodes.length} | EDGES: {edges.length} | ENGINE: R3F-INSTANCED
          </div>
        </div>
      </div>

      <AnimatePresence>
        {sidebarOpen && (
          <motion.aside
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
   
            className="w-[420px] border-l border-white/10 bg-black/90 backdrop-blur-2xl z-20 flex flex-col shadow-[-20px_0_50px_rgba(0,0,0,0.5)]"
          >
            <div className="p-8 border-b border-white/5 flex items-center justify-between">
              <h3 className="text-xs font-black text-accent uppercase tracking-[0.2em]">Operational Intelligence</h3>
              <button onClick={() => setSidebarOpen(false)} className="text-muted hover:text-accent transition-colors"><Icon name="x" size={20} /></button>
            </div>

            <div className="flex gap-4 px-8 border-b border-white/5 bg-white/5">
               <button 
                onClick={() => setSidebarTab('intel')}
   
                className={`pb-4 pt-4 text-[10px] font-black uppercase tracking-widest border-b-2 transition-all ${sidebarTab === 'intel' ? 'border-accent text-white' : 'border-transparent text-muted hover:text-text'}`}
               >
                 Findings
               </button>
               <button 
                onClick={() => setSidebarTab('chains')}
   
                className={`pb-4 pt-4 text-[10px] font-black uppercase tracking-widest border-b-2 transition-all ${sidebarTab === 'chains' ? 'border-accent text-white' : 'border-transparent text-muted hover:text-text'}`}
               >
                 Kill-Chains
               </button>
               <button 
                onClick={() => setSidebarTab('forensics')}
   
                className={`pb-4 pt-4 text-[10px] font-black uppercase tracking-widest border-b-2 transition-all ${sidebarTab === 'forensics' ? 'border-accent text-white' : 'border-transparent text-muted hover:text-text'}`}
               >
                 Forensics
               </button>
            </div>

            <div className="flex-1 overflow-y-auto p-8 scrollbar-cyber">
              {sidebarTab === 'intel' && selectedNode && (
                <div className="space-y-8">
                  <div>
                    <div className={`inline-block px-2 py-0.5 rounded text-[9px] uppercase font-black mb-3 tracking-widest ${
                      selectedNode.severity === 'high' || selectedNode.severity === 'critical' ? 'bg-red-500 text-white' : 'bg-accent text-black'
                    }`}>
                      {selectedNode.type}
                    </div>
                    <h4 className="text-xl font-bold text-text leading-tight mb-2">{selectedNode.label}</h4>
                    <div className="text-[10px] text-muted font-mono break-all opacity-60">{selectedNodeUrl}</div>
                  </div>

                  <section>
                    <h5 className="text-[10px] font-black text-white/30 uppercase tracking-[0.2em] mb-4">Operations</h5>
                    <div className="grid grid-cols-2 gap-3">
                      <button onClick={handleTriggerProbe} disabled={probing} className="bg-accent/10 border border-accent/20 text-accent text-[10px] font-bold py-3 rounded uppercase tracking-widest hover:bg-accent/20 transition-all">
                        {probing ? 'Probing...' : 'Forensic Probe'}
                      </button>
                      <button className="bg-white/5 border border-white/10 text-white text-[10px] font-bold py-3 rounded uppercase tracking-widest hover:bg-white/10 transition-all">Export Data</button>
                    </div>
                  </section>

                  <section>
                    <h5 className="text-[10px] font-black text-white/30 uppercase tracking-[0.2em] mb-4">Collaboration</h5>
                    <div className="space-y-3 mb-6">
                      {notes.map(n => (
                        <div key={n.id} className="p-4 bg-white/5 border border-white/5 rounded-lg">
                          <div className="flex items-center justify-between mb-2 text-[9px] font-mono uppercase opacity-40">
                            <span className="text-accent">{n.author}</span>
                            <span>{new Date(n.created_at).toLocaleDateString()}</span>
                          </div>
                          <p className="text-xs text-text/80 leading-relaxed">{n.note}</p>
                        </div>
                      ))}
                    </div>
                    <textarea value={newNote} onChange={(e) => setNewNote(e.target.value)} placeholder="ENTER DATA..." className="w-full bg-white/5 border border-white/10 rounded-lg p-4 text-xs text-text min-h-[100px] focus:border-accent/50 outline-none font-mono" />
                    <button onClick={handleAddNote} disabled={!newNote.trim()} className="w-full bg-accent text-black text-[10px] font-black py-3 mt-3 rounded uppercase tracking-[0.2em] hover:bg-white transition-colors">Submit Intel</button>
                  </section>
                </div>
              )}
              {sidebarTab === 'chains' && (
                <AttackChainVisualizer chains={chains} />
              )}
              {sidebarTab === 'forensics' && (
                <div className="space-y-4">
                  {selectedExchange ? (
                    <ForensicExchangeDetail exchange={selectedExchange} onBack={() => setSelectedExchange(null)} />
                  ) : (
                    exchanges.map(e => <ForensicExchangeItem key={e.exchange_id} exchange={e} onOpen={handleOpenForensic} />)
                  )}
                </div>
              )}
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </div>
  );
}
