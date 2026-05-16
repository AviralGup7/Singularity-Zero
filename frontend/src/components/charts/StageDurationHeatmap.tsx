import { useMemo } from 'react';
import type { Job } from '../../types/api';

interface HeatmapCell {
  jobId: string;
  jobLabel: string;
  stage: string;
  stageLabel: string;
  duration: number;
  status: string;
}

interface HeatmapRow {
  stage: string;
  stageLabel: string;
  cells: HeatmapCell[];
  stats: { min: number; max: number; mean: number; count: number };
}

type StageStats = Record<string, { duration_sec?: number; findings_count?: number }>;
type JobWithStageStats = Job & {
  stage_performance?: StageStats;
  per_module_stats?: StageStats;
};

const STAGE_ORDER = [
  'startup',
  'subdomains',
  'live_hosts',
  'urls',
  'recon_validation',
  'parameters',
  'ranking',
  'passive_scan',
  'active_scan',
  'semgrep',
  'nuclei',
  'access_control',
  'validation',
  'intelligence',
  'reporting',
];

const STAGE_LABELS: Record<string, string> = {
  startup: 'Startup',
  subdomains: 'Subdomain Recon',
  live_hosts: 'Live Host Discovery',
  urls: 'URL Discovery',
  recon_validation: 'Recon Validation',
  parameters: 'Parameter Discovery',
  ranking: 'Priority Assignment',
  passive_scan: 'Passive Scan',
  active_scan: 'Active Scan',
  semgrep: 'Semgrep Scan',
  nuclei: 'Nuclei Scan',
  access_control: 'Access Control',
  validation: 'Validation Runtime',
  intelligence: 'Intelligence',
  reporting: 'Reporting',
};

const STAGE_ALIASES: Record<string, string> = {
  priority: 'ranking',
};

function normalizeStageName(stageName: string): string {
  const normalized = String(stageName || '').trim().toLowerCase();
  if (!normalized) return '';
  // eslint-disable-next-line security/detect-object-injection
  return STAGE_ALIASES[normalized] ?? normalized;
}

export function StageDurationHeatmap({ jobs }: { jobs: Job[] }) {
  const heatmap = useMemo(() => {
    // Group by stage, collect durations
    const stageMap = new Map<string, HeatmapCell[]>();

    for (const job of jobs) {
      const stats = (job as JobWithStageStats).stage_performance || (job as JobWithStageStats).per_module_stats;
      if (!stats) continue;

      const jobId = job.id;
      const jobLabel = job.target_name || job.hostname || jobId.substring(0, 8);

   
      for (const [rawStage, data] of Object.entries(stats)) {
        const stage = normalizeStageName(rawStage);
        if (!stage) continue;
        const entry = data as { duration_sec?: number; findings_count?: number };
        const duration = entry.duration_sec ?? 0;

        if (!stageMap.has(stage)) {
          stageMap.set(stage, []);
        }
        stageMap.get(stage)!.push({
          jobId,
          jobLabel,
          stage,
  // eslint-disable-next-line security/detect-object-injection
          stageLabel: STAGE_LABELS[stage] || stage.replace(/_/g, ' '),
          duration,
          status: job.status,
        });
      }
    }

    const stages: string[] = STAGE_ORDER.filter((s) => stageMap.has(s));
    // Also add any stages that aren't in our preset list
    for (const key of stageMap.keys()) {
      if (!stages.includes(key)) stages.push(key);
    }

    const rows: HeatmapRow[] = stages.map((stage) => {
      const cells = stageMap.get(stage) ?? [];
      const durations = cells.map((c) => c.duration).filter((d) => d > 0);
      const stats = {
        min: durations.length > 0 ? Math.min(...durations) : 0,
        max: durations.length > 0 ? Math.max(...durations) : 0,
        mean: durations.length > 0 ? durations.reduce((a, b) => a + b, 0) / durations.length : 0,
        count: durations.length,
      };

  // eslint-disable-next-line security/detect-object-injection
      return { stage, stageLabel: STAGE_LABELS[stage] || stage.replace(/_/g, ' '), cells, stats };
    }).filter((r) => r.stats.mean > 0); // Only show stages with actual data

    return rows;
   
  }, [jobs]);

  if (heatmap.length === 0) {
    return (
      <div className="heatmap-empty">
        No stage duration data available. Run more jobs to build historical data.
      </div>
    );
  }

  const maxMean = Math.max(...heatmap.map((r) => r.stats.mean));

  return (
    <div className="stage-heatmap">
      <div className="stage-heatmap-header">
        <span className="heat-col-label">Stage</span>
  // eslint-disable-next-line security/detect-object-injection
        {heatmap[0]?.cells.map((cell) => (
          <span key={cell.jobId} className="heat-cell-header" title={cell.jobLabel}>
            {cell.jobLabel}
          </span>
        ))}
        <span className="heat-stats-header">Stats</span>
      </div>

      {heatmap.map((row) => {
   
        const allJobs = heatmap[0]?.cells ?? [];
   
        const cellMap = new Map(row.cells.map((c) => [c.jobId, c]));

        return (
          <div key={row.stage} className="stage-heatmap-row">
            <span className="heat-col-label" title={row.stageLabel}>
              {row.stageLabel}
            </span>

            {allJobs.map((jobCell) => {
              const cell = cellMap.get(jobCell.jobId);
              if (!cell || cell.duration === 0) {
                return (
                  <div key={jobCell.jobId} className="heat-cell heat-cell-empty" />
                );
              }

              const intensity = maxMean > 0 ? cell.duration / maxMean : 0;
              const h = Math.round(120 - 120 * Math.min(1, intensity)); // 120=green(fast), 0=red(slow)
              const color = `hsl(${h}, 70%, 45%)`;
              const bgColor = `hsla(${h}, 70%, 45%, 0.15)`;

              return (
                <div
                  key={jobCell.jobId}
                  className="heat-cell"
                  style={{ backgroundColor: bgColor, borderColor: color }}
                  title={`${row.stageLabel}: ${formatDuration(cell.duration)}`}
                >
                  <span className="heat-cell-value">{formatDuration(cell.duration)}</span>
                </div>
              );
            })}

            <div className="heat-stats" title={`Mean: ${formatDuration(row.stats.mean)} | Min: ${formatDuration(row.stats.min)} | Max: ${formatDuration(row.stats.max)} | Samples: ${row.stats.count}`}>
              <span><b>{formatDuration(row.stats.mean)}</b></span>
              <span>n={row.stats.count}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}
