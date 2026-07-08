import { motion } from 'framer-motion';
import type { StageTheaterNode } from '@/lib/stageTheaterUtils';
import type { VisualState } from '@/lib/visualState';
import { NODE_COLORS } from './constants';
import { resolveNodeVisualMode, resolveNodeVisualAnimation, resolveNodeTransition, formatStageStatus } from './helpers';

interface NodeRendererProps {
  nodes: Array<StageTheaterNode & { x: number; y: number; level: number; order: number }>;
  focusNodeId: string | null;
  visualState: VisualState;
}

export function NodeRenderer({ nodes, focusNodeId, visualState }: NodeRendererProps) {
  return (
    <>
      {nodes.map((node) => {
        const color = NODE_COLORS[node.status];
        const isRunning = node.status === 'running';
        const isFocused = focusNodeId === node.id;
        const nodeRadius = isFocused ? (isRunning ? 30 : 26) : (isRunning ? 26 : 22);
        const visualMode = resolveNodeVisualMode(node, visualState);
        const nodeTransition = resolveNodeTransition(visualMode, visualState);
        const nodeVisualAnimation = resolveNodeVisualAnimation(visualMode, visualState);
        return (
          <motion.g
            key={node.id}
            className={`stage-theater-node stage-theater-node--${node.status} ${isFocused ? 'stage-theater-node--focus' : ''}`}
            initial={false}
            animate={nodeVisualAnimation}
            transition={nodeTransition}
            style={{ transformBox: 'fill-box', transformOrigin: `${node.x}px ${node.y}px` }}
          >
            <motion.circle cx={node.x} cy={node.y} r={nodeRadius}
              fill={isRunning ? 'rgba(55, 246, 255, 0.12)' : 'rgba(10, 17, 28, 0.7)'}
              stroke={color} strokeWidth={isFocused ? 3.4 : isRunning ? 2.8 : 1.8}
              animate={isRunning ? { scale: [1, 1.12, 1], opacity: [0.6, 1, 0.6] } : node.status === 'error' ? { opacity: [0.85, 1, 0.85] } : undefined}
              transition={isRunning
                ? { duration: Math.max(0.5, 1.25 - visualState.intensity * 0.55), repeat: Number.POSITIVE_INFINITY, ease: 'easeInOut' }
                : node.status === 'error'
                  ? { duration: Math.max(0.3, 0.7 - visualState.urgency * 0.25), repeat: Number.POSITIVE_INFINITY, ease: 'easeInOut' }
                  : undefined}
            />
            {(isRunning || isFocused) && (
              <g className="stage-theater-rotor" transform={`translate(${node.x} ${node.y})`}>
                <circle cx={0} cy={0} r={nodeRadius + 12} className="stage-theater-rotor-ring" />
              </g>
            )}
            {isRunning && (
              <motion.circle cx={node.x} cy={node.y} r={nodeRadius + 6} fill="transparent"
                stroke={color} strokeWidth={1.2}
                animate={{ scale: [0.9, 1.25], opacity: [0.8, 0] }}
                transition={{ duration: Math.max(0.5, 1.2 - visualState.flow * 0.5), repeat: Number.POSITIVE_INFINITY, ease: 'easeOut' }} />
            )}
            {isFocused && (
              <motion.circle cx={node.x} cy={node.y} r={nodeRadius + 20} fill="transparent"
                stroke={color} strokeWidth={1.3}
                animate={{ scale: [0.9, 1.34], opacity: [0.52, 0] }}
                transition={{ duration: Math.max(0.62, 1.15 - visualState.intensity * 0.35), repeat: Number.POSITIVE_INFINITY, ease: 'easeOut' }} />
            )}
            <circle cx={node.x} cy={node.y} r={8} fill={color} className="stage-theater-node-core" />
            <text x={node.x} y={node.y + 52} textAnchor="middle" className="stage-theater-node-label">{node.label}</text>
            <text x={node.x} y={node.y + 70} textAnchor="middle" className="stage-theater-node-meta">{formatStageStatus(node)}</text>
            {(node.activeCount || node.completedCount || node.errorCount) && (
              <text x={node.x} y={node.y - 38} textAnchor="middle" className="stage-theater-node-stats">
                A {node.activeCount ?? 0} | C {node.completedCount ?? 0} | E {node.errorCount ?? 0}
              </text>
            )}
          </motion.g>
        );
      })}
    </>
  );
}
