import { useMemo } from 'react';
import { Icon } from '@/components/ui/Icon';
import type { CockpitNode, CockpitEdge } from '@/api/cockpit';

interface GraphLegendProps {
  nodes: CockpitNode[];
  edges: CockpitEdge[];
  meshHealth: { avg_latency_ms: number; peer_count: number } | null;
  migrations: { timestamp: number }[];
  now: number;
}

export function GraphLegend({ nodes, edges, meshHealth, migrations, now }: GraphLegendProps) {
  const recentMigrations = useMemo(() => migrations.filter((m) => now - m.timestamp < 30000).length, [migrations, now]);

  return (
    <div className="absolute bottom-8 left-8 z-10 flex flex-wrap gap-4" role="region" aria-label="Graph legend and status">
      <div className="flex items-center gap-4 rounded border border-line-muted bg-surface-2 px-4 py-2 font-mono text-[9px] uppercase tracking-widest text-text-secondary backdrop-blur-md" role="img" aria-label="Severity indicators">
        <div className="flex items-center gap-1.5">
          <div className="h-1.5 w-1.5 rounded-full bg-critical" aria-hidden="true" /> Critical
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-1.5 w-1.5 rounded-full bg-high" aria-hidden="true" /> High
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-1.5 w-1.5 rounded-full bg-medium" aria-hidden="true" /> Med
        </div>
      </div>
      {meshHealth && (
        <div className="flex items-center gap-4 rounded border border-line-muted bg-surface-2 px-4 py-2 font-mono text-[9px] uppercase tracking-widest text-accent backdrop-blur-md" role="status" aria-label={`Mesh health: latency ${meshHealth.avg_latency_ms}ms, ${meshHealth.peer_count} peers`}>
          <div className="flex items-center gap-1.5">
            <Icon name="activity" size={10} aria-hidden="true" /> Latency: <span className="tabular-nums">{meshHealth.avg_latency_ms}ms</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Icon name="server" size={10} aria-hidden="true" /> Peers: <span className="tabular-nums">{meshHealth.peer_count}</span>
          </div>
          {recentMigrations > 0 && (
            <div className="flex animate-pulse items-center gap-1.5 text-bad">
              <Icon name="gitBranch" size={10} aria-hidden="true" /> Migrations: <span className="tabular-nums">{recentMigrations}</span>
            </div>
          )}
        </div>
      )}
      <div className="rounded border border-line-muted bg-surface px-4 py-2 font-mono text-[9px] tracking-widest text-accent/40 backdrop-blur-md tabular-nums" aria-label={`Graph stats: ${nodes.length} nodes, ${edges.length} edges`}>
        NODES: {nodes.length} | EDGES: {edges.length} | ENGINE: R3F-INSTANCED
      </div>
    </div>
  );
}
