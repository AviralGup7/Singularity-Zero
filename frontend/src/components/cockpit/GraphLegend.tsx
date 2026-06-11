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
    <div className="absolute bottom-8 left-8 z-10 flex flex-wrap gap-4">
      <div className="flex items-center gap-4 rounded border border-white/5 bg-black/60 px-4 py-2 font-mono text-[9px] uppercase tracking-widest text-muted backdrop-blur-md">
        <div className="flex items-center gap-1.5">
          <div className="h-1.5 w-1.5 rounded-full bg-[#ff2d55]" /> Critical
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-1.5 w-1.5 rounded-full bg-[#ff6b35]" /> High
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-1.5 w-1.5 rounded-full bg-[#f7b731]" /> Med
        </div>
      </div>
      {meshHealth && (
        <div className="flex items-center gap-4 rounded border border-white/5 bg-black/60 px-4 py-2 font-mono text-[9px] uppercase tracking-widest text-accent backdrop-blur-md">
          <div className="flex items-center gap-1.5">
            <Icon name="activity" size={10} /> Latency: {meshHealth.avg_latency_ms}ms
          </div>
          <div className="flex items-center gap-1.5">
            <Icon name="server" size={10} /> Peers: {meshHealth.peer_count}
          </div>
          {recentMigrations > 0 && (
            <div className="flex animate-pulse items-center gap-1.5 text-[#ff2d55]">
              <Icon name="gitBranch" size={10} /> Migrations: {recentMigrations}
            </div>
          )}
        </div>
      )}
      <div className="rounded border border-white/5 bg-black/40 px-4 py-2 font-mono text-[9px] tracking-widest text-accent/40 backdrop-blur-md">
        NODES: {nodes.length} | EDGES: {edges.length} | ENGINE: R3F-INSTANCED
      </div>
    </div>
  );
}
