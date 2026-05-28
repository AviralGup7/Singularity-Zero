/* eslint-disable @typescript-eslint/no-explicit-any */
import { memo, useEffect, useMemo, useRef } from 'react';
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

  const sphereSegments = useMemo(() => {
    return nodes.length > 500 ? 8 : nodes.length > 150 ? 12 : 20;
  }, [nodes.length]);

  useEffect(() => {
    if (!meshRef.current || !pulseRef.current || !healthRef.current || !healthBgRef.current) return;
    nodes.forEach((node, index) => {
      const [x, y, z] = node.position;
      const severityScale = node.severity === 'critical' ? 1.6
        : node.severity === 'high' ? 1.3
        : node.severity === 'medium' ? 1.05
        : node.severity === 'low' ? 0.85
        : 0.7;
      const baseSize = (node.type === 'finding' ? 0.78 : node.type === 'subdomain' ? 0.64 : 0.52) * severityScale;
      const selected = node.id === selectedNodeId;
      const hovered = node.id === hoveredNodeId;

      // Pulse hover lifts: lift slightly in Y when hovered
      const posY = hovered ? y + 0.8 : y;
      const finalScale = selected ? baseSize * 1.45 : hovered ? baseSize * 1.3 : baseSize;

      temp.position.set(x, posY, z);
      temp.scale.setScalar(finalScale);
      temp.updateMatrix();
      meshRef.current?.setMatrixAt(index, temp.matrix);
      meshRef.current?.setColorAt(index, new Color(SEVERITY_COLORS[node.severity] || SEVERITY_COLORS.info));

      // Selected pulse ring
      temp.scale.setScalar(selected ? baseSize * 2.2 : 0.001);
      temp.updateMatrix();
      pulseRef.current?.setMatrixAt(index, temp.matrix);
      pulseRef.current?.setColorAt(index, new Color('#d8f3ff'));

      // Health bar background track
      const barY = posY + finalScale + 0.35;
      const healthVal = nodeHealth(node);
      
      temp.position.set(x, barY, z);
      temp.scale.set(1.2 * finalScale, 1, 1);
      temp.updateMatrix();
      healthBgRef.current?.setMatrixAt(index, temp.matrix);

      // Active health bar
      temp.position.set(x - (1.2 * finalScale * (1 - healthVal)) / 2, barY, z + 0.01);
      temp.scale.set(1.2 * finalScale * healthVal, 1, 1);
      temp.updateMatrix();
      healthRef.current?.setMatrixAt(index, temp.matrix);

      // Health color mapping
      const healthColor = healthVal < 0.35 ? '#ff2d55' : healthVal < 0.7 ? '#f7b731' : '#10b981';
      healthRef.current?.setColorAt(index, new Color(healthColor));
    });

    meshRef.current.instanceMatrix.needsUpdate = true;
    if (meshRef.current.instanceColor) {
      meshRef.current.instanceColor.needsUpdate = true;
    }
    pulseRef.current.instanceMatrix.needsUpdate = true;
    if (pulseRef.current.instanceColor) {
      pulseRef.current.instanceColor.needsUpdate = true;
    }
    healthBgRef.current.instanceMatrix.needsUpdate = true;
    healthRef.current.instanceMatrix.needsUpdate = true;
    if (healthRef.current.instanceColor) {
      healthRef.current.instanceColor.needsUpdate = true;
    }
  }, [nodes, selectedNodeId, hoveredNodeId, temp]);

  useFrame((state) => {
    if (!pulseRef.current || !healthRef.current || !healthBgRef.current) return;
    const time = state.clock.elapsedTime;
    const wave = 1 + Math.sin(time * 3.4) * 0.1;

    nodes.forEach((node, index) => {
      const selected = node.id === selectedNodeId;
      const hovered = node.id === hoveredNodeId;

      if (selected || hovered) {
        const severityScale = node.severity === 'critical' ? 1.6
          : node.severity === 'high' ? 1.3
          : node.severity === 'medium' ? 1.05
          : node.severity === 'low' ? 0.85
          : 0.7;
        const baseSize = (node.type === 'finding' ? 0.78 : node.type === 'subdomain' ? 0.64 : 0.52) * severityScale;
        const [x, y, z] = node.position;

        const floatOffset = hovered ? Math.sin(time * 5) * 0.15 : 0;
        const posY = (hovered ? y + 0.8 : y) + floatOffset;
        const finalScale = (selected ? baseSize * 1.45 : baseSize * 1.3) * wave;

        temp.position.set(x, posY, z);
        temp.scale.setScalar(finalScale);
        temp.updateMatrix();
        meshRef.current?.setMatrixAt(index, temp.matrix);

        if (selected) {
          temp.scale.setScalar(baseSize * 2.1 * wave);
          temp.updateMatrix();
          pulseRef.current?.setMatrixAt(index, temp.matrix);
        }

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
      }
    });

    if (meshRef.current) {
      meshRef.current.instanceMatrix.needsUpdate = true;
    }
    if (pulseRef.current) {
      pulseRef.current.instanceMatrix.needsUpdate = true;
    }
    if (healthBgRef.current) {
      healthBgRef.current.instanceMatrix.needsUpdate = true;
    }
    if (healthRef.current) {
      healthRef.current.instanceMatrix.needsUpdate = true;
    }
  });

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
        onClick={(event: ThreeEvent<MouseEvent>) => {
          event.stopPropagation();
          const id = event.instanceId === undefined ? null : nodes[event.instanceId]?.id;
          if (id) onSelectNode(id);
        }}
        onPointerMove={(event: ThreeEvent<PointerEvent>) => {
          event.stopPropagation();
          const id = event.instanceId === undefined ? null : nodes[event.instanceId]?.id;
          onHoverNode(id);
        }}
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

  return (
    <div className={`relative ${className ?? 'h-full w-full'}`}>
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
