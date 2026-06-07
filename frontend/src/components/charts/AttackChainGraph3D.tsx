/* eslint-disable @typescript-eslint/no-explicit-any */
import { memo, useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import type { ThreeEvent } from '@react-three/fiber';
import { Color, Object3D, Vector3 } from 'three';
import * as THREE from 'three';
import { OrbitControls as ThreeOrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import type { CockpitEdge, CockpitNode } from '@/api/cockpit';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff2d55',
  high: '#ff6b35',
  medium: '#f7b731',
  low: '#4da3ff',
  info: '#8aa4b8',
};

const TYPE_LANES: Record<CockpitNode['type'], number> = {
  subdomain: -18,
  endpoint: 0,
  finding: 18,
};

interface PositionedNode extends CockpitNode {
  position: [number, number, number];
}

interface AttackChainGraph3DProps {
  nodes: CockpitNode[];
  edges: CockpitEdge[];
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  onSelectNode: (id: string) => void;
  onHoverNode: (id: string | null) => void;
  className?: string;
}

function nodeHealth(node: CockpitNode): number {
  const value = node.metadata?.health;
  return typeof value === 'number' ? Math.max(0, Math.min(1, value)) : 0.82;
}

function severityScaleOf(node: CockpitNode): number {
  switch (node.severity) {
    case 'critical': return 1.6;
    case 'high': return 1.3;
    case 'medium': return 1.05;
    case 'low': return 0.85;
    default: return 0.7;
  }
}

function typeBaseSize(node: CockpitNode): number {
  return node.type === 'finding' ? 0.78 : node.type === 'subdomain' ? 0.64 : 0.52;
}

function arrangeNodes(nodes: CockpitNode[]): PositionedNode[] {
  const byType = nodes.reduce<Record<string, CockpitNode[]>>((acc, node) => {
    (acc[node.type] ||= []).push(node);
    return acc;
  }, {});

  return nodes.map((node) => {
    const lane = byType[node.type] || [];
    const index = Math.max(0, lane.findIndex((item) => item.id === node.id));
    const count = Math.max(1, lane.length);
    const angle = (index / count) * Math.PI * 2;
    const radius = Math.max(5, Math.sqrt(count) * 2.2);
    const laneX = TYPE_LANES[node.type] ?? 0;
    const jitter = node.type === 'finding' ? 2.5 : 0;
    return {
      ...node,
      position: [
        laneX + Math.sin(angle * 3) * jitter,
        Math.cos(angle) * radius,
        Math.sin(angle) * radius,
      ],
    };
  });
}

function GraphEdges({ edges, nodes }: { edges: CockpitEdge[]; nodes: PositionedNode[] }) {
  const positions = useMemo(() => {
    const index = new Map(nodes.map((node) => [node.id, node.position]));
    const values: number[] = [];
    for (const edge of edges) {
      const source = index.get(edge.source);
      const target = index.get(edge.target);
      if (source && target) values.push(...source, ...target);
    }
    return new Float32Array(values);
  }, [edges, nodes]);

  if (positions.length === 0) return null;

  return (
    <lineSegments frustumCulled={true}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <lineBasicMaterial color="#35506b" transparent opacity={0.38} />
    </lineSegments>
  );
}

function LaneGuides() {
  const positions = useMemo(() => new Float32Array([
    -18, -14, 0, -18, 14, 0,
    0, -14, 0, 0, 14, 0,
    18, -14, 0, 18, 14, 0,
    -22, 0, 0, 22, 0, 0,
  ]), []);

  return (
    <lineSegments frustumCulled={true}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <lineBasicMaterial color="#25435a" transparent opacity={0.45} />
    </lineSegments>
  );
}

/**
 * Write a single node's full transform (sphere + pulse + health track + bar) into the
 * 4 instanced meshes. The caller passes the node, its index, and whether it is the
 * currently hovered or selected node. This is the hot path used by `useFrame` and the
 * baseline layout effect, and it deliberately avoids iterating the rest of the node
 * array so we can keep 60 FPS with 5,000+ instances.
 */
function writeNodeMatrices(
  node: PositionedNode,
  index: number,
  isHovered: boolean,
  isSelected: boolean,
  wave: number,
  temp: Object3D,
  meshRef: any,
  pulseRef: any,
  healthBgRef: any,
  healthRef: any,
) {
  const [x, y, z] = node.position;
  const baseSize = typeBaseSize(node) * severityScaleOf(node);
  const floatOffset = isHovered ? Math.sin(performance.now() * 0.005) * 0.15 : 0;
  const posY = (isHovered ? y + 0.8 : y) + floatOffset;
  const finalScale = isSelected
    ? baseSize * 1.45 * wave
    : isHovered
      ? baseSize * 1.3 * wave
      : baseSize;

  temp.position.set(x, posY, z);
  temp.scale.setScalar(finalScale);
  temp.updateMatrix();
  meshRef.current?.setMatrixAt(index, temp.matrix);
  meshRef.current?.setColorAt(index, new Color(SEVERITY_COLORS[node.severity] || SEVERITY_COLORS.info));

  const pulseScale = isSelected ? baseSize * 2.1 * wave : 0.001;
  temp.scale.setScalar(pulseScale);
  temp.updateMatrix();
  pulseRef.current?.setMatrixAt(index, temp.matrix);
  pulseRef.current?.setColorAt(index, new Color('#d8f3ff'));

  const barY = posY + finalScale + 0.35;
  const healthVal = nodeHealth(node);

  temp.position.set(x, barY, z);
  temp.scale.set(1.2 * finalScale, 1, 1);
  temp.updateMatrix();
  healthBgRef.current?.setMatrixAt(index, temp.matrix);

  temp.position.set(x - (1.2 * finalScale * (1 - healthVal)) / 2, barY, z + 0.01);
  temp.scale.set(1.2 * finalScale * healthVal, 1, 1);
  temp.updateMatrix();
  healthRef.current?.setMatrixAt(index, temp.matrix);

  const healthColor = healthVal < 0.35 ? '#ff2d55' : healthVal < 0.7 ? '#f7b731' : '#10b981';
  healthRef.current?.setColorAt(index, new Color(healthColor));
}

function flushInstanceNeedsUpdate(
  meshRef: any,
  pulseRef: any,
  healthBgRef: any,
  healthRef: any,
) {
  if (meshRef.current) meshRef.current.instanceMatrix.needsUpdate = true;
  if (pulseRef.current) pulseRef.current.instanceMatrix.needsUpdate = true;
  if (healthBgRef.current) healthBgRef.current.instanceMatrix.needsUpdate = true;
  if (healthRef.current) healthRef.current.instanceMatrix.needsUpdate = true;
  if (meshRef.current?.instanceColor) meshRef.current.instanceColor.needsUpdate = true;
  if (pulseRef.current?.instanceColor) pulseRef.current.instanceColor.needsUpdate = true;
  if (healthRef.current?.instanceColor) healthRef.current.instanceColor.needsUpdate = true;
}

function GraphNodes({
  nodes,
  selectedNodeId,
  hoveredNodeId,
  onSelectNode,
  onHoverNode,
}: {
  nodes: PositionedNode[];
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  onSelectNode: (id: string) => void;
  onHoverNode: (id: string | null) => void;
}) {
  const meshRef = useRef<any>(null);
  const pulseRef = useRef<any>(null);
  const healthRef = useRef<any>(null);
  const healthBgRef = useRef<any>(null);
  const temp = useMemo(() => new Object3D(), []);

  // Index lookup so we can convert `event.instanceId` to a node O(1).
  const idByIndexRef = useRef<string[]>([]);
  useEffect(() => {
    idByIndexRef.current = nodes.map((n) => n.id);
  }, [nodes]);

  // Track which nodes were "drawn last frame" so we can avoid touching instances
  // that haven't changed (selection, hover, animation phase). This is the single
  // biggest perf optimization: we only update the 1-2 nodes that actually changed
  // instead of all 5,000.
  const lastDrawnIndexRef = useRef<number>(-1);
  const lastSelectedIdRef = useRef<string | null>(null);
  const lastHoveredIdRef = useRef<string | null>(null);
  const lastWaveRef = useRef<number>(1);

  const sphereSegments = useMemo(() => {
    return nodes.length > 500 ? 8 : nodes.length > 150 ? 12 : 20;
  }, [nodes.length]);

  // Baseline layout: when `nodes` itself changes, only the nodes whose index
  // shifted need rewriting. We rebuild everything cheaply using the same
  // helper that the frame loop uses; the cost is paid once per change.
  useEffect(() => {
    if (!meshRef.current || !pulseRef.current || !healthRef.current || !healthBgRef.current) return;
    const selectedIndex = selectedNodeId
      ? nodes.findIndex((n) => n.id === selectedNodeId)
      : -1;
    const hoveredIndex = hoveredNodeId
      ? nodes.findIndex((n) => n.id === hoveredNodeId)
      : -1;
    for (let i = 0; i < nodes.length; i++) {
      // Index `i` is bounded by `nodes.length` so this is safe by construction.
      // eslint-disable-next-line security/detect-object-injection
      const node = nodes[i];
      writeNodeMatrices(
        node,
        i,
        i === hoveredIndex,
        i === selectedIndex,
        1,
        temp,
        meshRef,
        pulseRef,
        healthBgRef,
        healthRef,
      );
    }
    flushInstanceNeedsUpdate(meshRef, pulseRef, healthBgRef, healthRef);
    lastDrawnIndexRef.current = -1;
    lastSelectedIdRef.current = selectedNodeId;
    lastHoveredIdRef.current = hoveredNodeId;
    lastWaveRef.current = 1;
  }, [nodes, selectedNodeId, hoveredNodeId, temp]);

  /**
   * Per-frame update. We only touch the 1-2 instances that are interactive or
   * animated. Idle nodes have their matrices baked from the effect above and we
   * never read or write to them again until selection/hover changes. This drops
   * the per-frame cost from O(n) to O(1) regardless of node count.
   */
  useFrame((state) => {
    if (!meshRef.current || !pulseRef.current || !healthRef.current || !healthBgRef.current) return;
    const time = state.clock.elapsedTime;
    const wave = 1 + Math.sin(time * 3.4) * 0.1;

    const hoveredIndex = hoveredNodeId
      ? nodes.findIndex((n) => n.id === hoveredNodeId)
      : -1;
    const selectedIndex = selectedNodeId
      ? nodes.findIndex((n) => n.id === selectedNodeId)
      : -1;

    // Cheap wave delta: only redraw interactive nodes when the wave amplitude
    // has actually changed since the last frame.
    const waveChanged = Math.abs(wave - lastWaveRef.current) > 0.0005;
    const selectionChanged = lastSelectedIdRef.current !== selectedNodeId;
    const hoverChanged = lastHoveredIdRef.current !== hoveredNodeId;
    const lastDrawnIndex = lastDrawnIndexRef.current;

    const needsInteractiveRedraw = waveChanged || selectionChanged || hoverChanged;

    if (selectedIndex >= 0 && needsInteractiveRedraw) {
      writeNodeMatrices(
        // Index is bounded by `findIndex` result.
        // eslint-disable-next-line security/detect-object-injection
        nodes[selectedIndex],
        selectedIndex,
        selectedIndex === hoveredIndex,
        true,
        wave,
        temp,
        meshRef,
        pulseRef,
        healthBgRef,
        healthRef,
      );
    }
    if (hoveredIndex >= 0 && hoveredIndex !== selectedIndex && needsInteractiveRedraw) {
      writeNodeMatrices(
        // eslint-disable-next-line security/detect-object-injection
        nodes[hoveredIndex],
        hoveredIndex,
        true,
        false,
        wave,
        temp,
        meshRef,
        pulseRef,
        healthBgRef,
        healthRef,
      );
    }
    // Wave animation only animates the selected/hovered node, so the wave
    // check above is the only per-frame work we ever do.
    if (selectionChanged || hoverChanged) {
      // Reset the previously-drawn node back to its baseline transform so
      // it doesn't keep the hover/select styling.
      if (lastDrawnIndex >= 0 && lastDrawnIndex < nodes.length && lastDrawnIndex !== selectedIndex && lastDrawnIndex !== hoveredIndex) {
        writeNodeMatrices(
          // eslint-disable-next-line security/detect-object-injection
          nodes[lastDrawnIndex],
          lastDrawnIndex,
          false,
          false,
          1,
          temp,
          meshRef,
          pulseRef,
          healthBgRef,
          healthRef,
        );
      }
    }

    if (needsInteractiveRedraw) {
      flushInstanceNeedsUpdate(meshRef, pulseRef, healthBgRef, healthRef);
    }

    lastDrawnIndexRef.current = selectedIndex >= 0 ? selectedIndex : hoveredIndex;
    lastSelectedIdRef.current = selectedNodeId;
    lastHoveredIdRef.current = hoveredNodeId;
    lastWaveRef.current = wave;
  });

  const onInstanceClick = useCallback((event: ThreeEvent<MouseEvent>) => {
    event.stopPropagation();
    const id = event.instanceId === undefined ? null : idByIndexRef.current[event.instanceId];
    if (id) onSelectNode(id);
  }, [onSelectNode]);

  const onInstanceMove = useCallback((event: ThreeEvent<PointerEvent>) => {
    event.stopPropagation();
    const id = event.instanceId === undefined ? null : idByIndexRef.current[event.instanceId];
    onHoverNode(id);
  }, [onHoverNode]);

  return (
    <>
      <instancedMesh
        ref={pulseRef}
        args={[new THREE.BufferGeometry(), new THREE.Material(), Math.max(1, nodes.length)]}
        frustumCulled={true}
      >
        <sphereGeometry args={[0.5, sphereSegments, sphereSegments]} />
        <meshBasicMaterial transparent opacity={0.18} toneMapped={false} />
      </instancedMesh>
      <instancedMesh
        ref={healthBgRef}
        args={[new THREE.BufferGeometry(), new THREE.Material(), Math.max(1, nodes.length)]}
        frustumCulled={true}
      >
        <boxGeometry args={[1, 0.12, 0.12]} />
        <meshBasicMaterial color="#1a1a2e" transparent opacity={0.3} toneMapped={false} />
      </instancedMesh>
      <instancedMesh
        ref={healthRef}
        args={[new THREE.BufferGeometry(), new THREE.Material(), Math.max(1, nodes.length)]}
        frustumCulled={true}
      >
        <boxGeometry args={[1, 0.12, 0.12]} />
        <meshBasicMaterial transparent opacity={0.85} toneMapped={false} />
      </instancedMesh>
      <instancedMesh
        ref={meshRef}
        args={[new THREE.BufferGeometry(), new THREE.Material(), Math.max(1, nodes.length)]}
        onClick={onInstanceClick}
        onPointerMove={onInstanceMove}
        onPointerOut={() => onHoverNode(null)}
        frustumCulled={true}
      >
        <sphereGeometry args={[0.5, sphereSegments, sphereSegments]} />
        <meshStandardMaterial emissiveIntensity={0.9} metalness={0.55} roughness={0.28} />
      </instancedMesh>
    </>
  );
}

function CameraRig({ selected }: { selected?: PositionedNode }) {
  const { camera } = useThree();
  useEffect(() => {
    if (!selected) return;
    const target = new Vector3(...selected.position);
    const offset = new Vector3(0, 3, 12);
    camera.position.lerp(target.clone().add(offset), 0.75);
    camera.lookAt(target);
  }, [camera, selected]);
  return null;
}

function OrbitRig() {
  const { camera, gl } = useThree();
  const controlsRef = useRef<any>(null);

  useEffect(() => {
    controlsRef.current = new ThreeOrbitControls(camera, gl.domElement);
    controlsRef.current.enableDamping = true;
    controlsRef.current.dampingFactor = 0.08;
    controlsRef.current.minDistance = 8;
    controlsRef.current.maxDistance = 95;
    return () => controlsRef.current?.dispose();
  }, [camera, gl]);

  useFrame(() => controlsRef.current?.update());
  return null;
}

interface SceneProps {
  nodes: PositionedNode[];
  edges: CockpitEdge[];
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  onSelectNode: (id: string) => void;
  onHoverNode: (id: string | null) => void;
}

function Scene({
  nodes,
  edges,
  selectedNodeId,
  hoveredNodeId,
  onSelectNode,
  onHoverNode,
}: SceneProps) {
  const selected = nodes.find((node) => node.id === selectedNodeId);

  return (
    <>
      <color attach="background" args={['#05070b']} />
      <fog attach="fog" args={['#05070b', 30, 82]} />
      <ambientLight intensity={0.35} />
      <pointLight position={[12, 15, 14]} intensity={2.2} color="#7dd3fc" />
      <pointLight position={[-18, -10, -18]} intensity={1.1} color="#ff6b35" />
      <LaneGuides />
      <GraphEdges edges={edges} nodes={nodes} />
      <GraphNodes
        nodes={nodes}
        selectedNodeId={selectedNodeId}
        hoveredNodeId={hoveredNodeId}
        onSelectNode={onSelectNode}
        onHoverNode={onHoverNode}
      />
      <CameraRig selected={selected} />
      <perspectiveCamera makeDefault position={[0, 0, 42]} fov={48} />
      <OrbitRig />
    </>
  );
}

/**
 * Returns true when the device GPU and viewport make a 3D cockpit viable. The 3D
 * view is desktop/tablet only; on small viewports we render a 2D fallback so
 * operators can still triage on phones (see `Cockpit2DFallback`).
 */
function useCanRender3D(): boolean {
  const supportsWebGL = useMemo(() => {
    if (typeof window === 'undefined') return false;
    try {
      const canvas = document.createElement('canvas');
      return Boolean(
        window.WebGLRenderingContext &&
        (canvas.getContext('webgl2') || canvas.getContext('webgl')),
      );
    } catch {
      return false;
    }
  }, []);

  const [isWide] = useIsWideViewport(720);
  return supportsWebGL && isWide;
}

function useIsWideViewport(minWidth: number): [boolean, (v: boolean) => void] {
  const [wide, setWide] = useState<boolean>(() => {
    if (typeof window === 'undefined') return true;
    return window.innerWidth >= minWidth;
  });
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia(`(min-width: ${minWidth}px)`);
    const handler = (e: MediaQueryListEvent) => setWide(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [minWidth]);
  return [wide, setWide];
}

function Cockpit2DFallback({ nodes, edges, selectedNodeId, hoveredNodeId, onSelectNode, onHoverNode, className }: AttackChainGraph3DProps) {
  const arranged = useMemo(() => arrangeNodes(nodes), [nodes]);
  const focused = hoveredNodeId || selectedNodeId;
  return (
    <div className={`relative ${className ?? 'h-full w-full'} overflow-auto bg-[#05070b]`}>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 p-4">
        {arranged.length === 0 && (
          <div className="text-muted text-center col-span-full p-12 text-xs uppercase tracking-[0.3em]">
            No data points detected
          </div>
        )}
        {arranged.map((n) => (
          <button
            key={n.id}
            type="button"
            onClick={() => onSelectNode(n.id)}
            onMouseEnter={() => onHoverNode(n.id)}
            onMouseLeave={() => onHoverNode(null)}
            className={`text-left rounded-lg border p-3 transition-all ${
              focused === n.id
                ? 'border-accent bg-accent/10 shadow-[0_0_18px_rgba(0,255,244,0.18)]'
                : 'border-white/10 bg-black/40 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between text-[9px] font-black uppercase tracking-widest mb-1">
              <span className="text-accent">{n.type}</span>
              <span style={{ color: SEVERITY_COLORS[n.severity] || SEVERITY_COLORS.info }}>
                {n.severity}
              </span>
            </div>
            <div className="text-xs font-bold text-text truncate">{n.label}</div>
            <div className="mt-2 h-1 overflow-hidden rounded bg-white/10">
              <div
                className="h-full bg-cyan-300"
                style={{ width: `${Math.round(nodeHealth(n) * 100)}%` }}
              />
            </div>
            <div className="mt-1 font-mono text-[9px] uppercase text-slate-400">
              Health {Math.round(nodeHealth(n) * 100)}%
            </div>
          </button>
        ))}
      </div>
      {edges.length > 0 && (
        <div className="px-4 pb-4 text-[10px] font-mono text-muted">
          {edges.length} relationship{edges.length === 1 ? '' : 's'} detected. Switch to desktop for the 3D view.
        </div>
      )}
    </div>
  );
}

export const AttackChainGraph3D = memo(function AttackChainGraph3D({
  nodes,
  edges,
  selectedNodeId,
  hoveredNodeId,
  onSelectNode,
  onHoverNode,
  className,
}: AttackChainGraph3DProps) {
  const arrangedNodes = useMemo(() => arrangeNodes(nodes), [nodes]);
  const hudNode = useMemo(
    () => arrangedNodes.find((node) => node.id === hoveredNodeId) || arrangedNodes.find((node) => node.id === selectedNodeId),
    [arrangedNodes, hoveredNodeId, selectedNodeId],
  );
  const health = hudNode ? Math.round(nodeHealth(hudNode) * 100) : 0;
  const canRender3D = useCanRender3D();

  return (
    <div className={`relative ${className ?? 'h-full w-full'}`}>
      {canRender3D ? (
        <Canvas dpr={[1, 1.75]} gl={{ antialias: true, powerPreference: 'high-performance' }}>
          <Scene
            nodes={arrangedNodes}
            edges={edges}
            selectedNodeId={selectedNodeId}
            hoveredNodeId={hoveredNodeId}
            onSelectNode={onSelectNode}
            onHoverNode={onHoverNode}
          />
        </Canvas>
      ) : (
        <Cockpit2DFallback
          nodes={nodes}
          edges={edges}
          selectedNodeId={selectedNodeId}
          hoveredNodeId={hoveredNodeId}
          onSelectNode={onSelectNode}
          onHoverNode={onHoverNode}
          className={className}
        />
      )}
      {hudNode && (
        <div className="pointer-events-none absolute right-4 top-4 w-56 rounded border border-cyan-300/40 bg-black/85 p-3 text-left shadow-[0_0_28px_rgba(56,189,248,0.18)] backdrop-blur-xl">
          <div className="mb-1 flex items-center justify-between gap-3">
            <span className="text-[9px] font-black uppercase tracking-[0.18em] text-cyan-200">{hudNode.type}</span>
            <span className="text-[9px] font-black uppercase tracking-[0.16em]" style={{ color: SEVERITY_COLORS[hudNode.severity] || SEVERITY_COLORS.info }}>
              {hudNode.severity}
            </span>
          </div>
          <div className="truncate text-xs font-bold text-white">{hudNode.label}</div>
          <div className="mt-2 h-1.5 overflow-hidden rounded bg-white/10">
            <div className="h-full rounded bg-cyan-300" style={{ width: `${health}%` }} />
          </div>
          <div className="mt-1 font-mono text-[9px] uppercase tracking-wider text-slate-400">Health {health}%</div>
        </div>
      )}
    </div>
  );
});

export type { PositionedNode };
