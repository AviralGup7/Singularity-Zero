import { linkVertical } from 'd3-shape';
import { useMemo  } from 'react';
import type {CSSProperties} from 'react';
import { useVisual } from '@/hooks/useVisual';
import type { StageTheaterNode } from '@/lib/stageTheaterUtils';
import { TREE_LEVELS, TREE_EDGES, AMBIENT_LOG_LINES } from './constants';
import { EdgeRenderer } from './EdgeRenderer';
import { NodeRenderer } from './NodeRenderer';

interface StageTheaterProps {
  nodes: StageTheaterNode[];
  className?: string;
}

export function StageTheater({ nodes, className }: StageTheaterProps) {
  const { state: visualState } = useVisual();

  const dimensions = useMemo(() => {
    const maxBreadth = Math.max(...TREE_LEVELS.map((level) => level.length), 1);
    const levelCount = Math.max(TREE_LEVELS.length, 1);
    const paddingX = 150;
    const paddingY = 118;
    const width = Math.max(1720, 1180 + maxBreadth * 260);
    const height = Math.max(760, paddingY * 2 + Math.max(levelCount - 1, 1) * 96);
    return { width, height, paddingX, paddingY };
  }, []);

  const stageTheaterStyle = useMemo(() => ({
    '--stage-theater-height': `${dimensions.height}px`,
    '--stage-theater-min-width': `${dimensions.width}px`,
  } as CSSProperties), [dimensions.height, dimensions.width]);

  const positionedNodes = useMemo(() => {
    const ordered = [...nodes];
    const nodeById = new Map(ordered.map((node) => [node.id, node]));
    const levelCount = Math.max(TREE_LEVELS.length, 1);
    const laneHeight = levelCount > 1
      ? (dimensions.height - dimensions.paddingY * 2) / (levelCount - 1)
      : 0;

    const layoutNodes: Array<StageTheaterNode & { x: number; y: number; level: number; order: number }> = [];

    TREE_LEVELS.forEach((level, levelIndex) => {
      const levelWidth = dimensions.width - dimensions.paddingX * 2;
      const gap = level.length > 0 ? levelWidth / (level.length + 1) : levelWidth;
      level.forEach((stageId, orderIndex) => {
        const node = nodeById.get(stageId);
        if (!node) return;
        layoutNodes.push({
          ...node, x: Math.round(dimensions.paddingX + gap * (orderIndex + 1)),
          y: Math.round(dimensions.paddingY + laneHeight * levelIndex), level: levelIndex, order: orderIndex,
        });
      });
    });

    const laidOutIds = new Set(layoutNodes.map((node) => node.id));
    const orphans = ordered.filter((node) => !laidOutIds.has(node.id));
    if (orphans.length > 0) {
      const orphanGap = (dimensions.width - dimensions.paddingX * 2) / (orphans.length + 1);
      orphans.forEach((node, orphanIndex) => {
        layoutNodes.push({
          ...node, x: Math.round(dimensions.paddingX + orphanGap * (orphanIndex + 1)),
          y: dimensions.height - dimensions.paddingY, level: levelCount, order: orphanIndex,
        });
      });
    }
    return layoutNodes.sort((a, b) => a.level - b.level || a.order - b.order);
  }, [nodes, dimensions.height, dimensions.paddingX, dimensions.paddingY, dimensions.width]);

  const links = useMemo(() => {
    const connector = linkVertical<{ source: [number, number]; target: [number, number] }, [number, number]>()
      .x((point) => point[0]).y((point) => point[1]);
    const nodeById = new Map(positionedNodes.map((node) => [node.id, node]));

    return TREE_EDGES
      .map(([sourceId, targetId]) => {
        const source = nodeById.get(sourceId);
        const target = nodeById.get(targetId);
        if (!source || !target) return null;
        const d = connector({ source: [source.x, source.y], target: [target.x, target.y] }) ?? '';
        return { id: `${sourceId}-${targetId}`, d, isFlowing: source.status === 'running' || target.status === 'running', hasFailure: source.status === 'error' || target.status === 'error' };
      })
      .filter((edge): edge is { id: string; d: string; isFlowing: boolean; hasFailure: boolean } => edge !== null);
  }, [positionedNodes]);

  const focusNodeId = useMemo(() => {
    const running = positionedNodes.filter((node) => node.status === 'running');
    if (running.length > 0) return [...running].sort((a, b) => b.percent - a.percent)[0].id;
    return positionedNodes.find((node) => node.status === 'error')?.id ?? null;
  }, [positionedNodes]);

  return (
    <div className={`stage-theater ${className ?? ''}`} style={stageTheaterStyle}>
      <div className="stage-theater-ambient" aria-hidden="true">
        <div className="stage-theater-grid-overlay" />
        <div className="stage-theater-scanlines-overlay" />
        <div className="stage-theater-ghost-logs">
          {AMBIENT_LOG_LINES.map((line, index) => (
            <span key={`${line}-${index}`} className="stage-theater-ghost-line" style={{ animationDelay: `${index * 0.32}s` }}>{line}</span>
          ))}
        </div>
      </div>
      <svg className="stage-theater-svg" viewBox={`0 0 ${dimensions.width} ${dimensions.height}`}
        preserveAspectRatio="xMidYMid meet" role="img" aria-label="Live pipeline stage theater"
      >
        <EdgeRenderer links={links} visualState={visualState} />
        <NodeRenderer nodes={positionedNodes} focusNodeId={focusNodeId} visualState={visualState} />
      </svg>
    </div>
  );
}
