import { useEffect, useMemo, useRef } from 'react';
import type { Job } from '@/types/api';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';

const STAGE_ORDER = [
  'startup',
  'subdomains',
  'live_hosts',
  'urls',
  'parameters',
  'ranking',
  'passive_scan',
  'active_scan',
  'nuclei',
  'access_control',
  'validation',
  'intelligence',
  'reporting',
];

const STAGE_ALIASES = new Map<string, string>([
  ['priority', 'ranking'],
]);

function normalizeStageName(stageName: string | undefined): string {
  const normalized = String(stageName || '').trim().toLowerCase();
  if (!normalized) return '';
  return STAGE_ALIASES.get(normalized) ?? normalized;
}

   
function resolveStageOrder(jobs: Job[]): string[] {
   
  const order = [...STAGE_ORDER];
  const seen = new Set(order);

  const addStage = (stageName: string | undefined) => {
    const normalized = normalizeStageName(stageName);
    if (!normalized || seen.has(normalized)) return;
    order.push(normalized);
    seen.add(normalized);
  };

  for (const job of jobs) {
    addStage(job.stage);
    for (const entry of job.stage_progress ?? []) {
      addStage(entry.stage);
    }
  }

  return order;
}

interface GsapTimeline {
  kill: () => void;
  fromTo: (target: unknown, fromVars: object, toVars: object, position?: unknown) => GsapTimeline;
}

interface GsapInstance {
  timeline: (config?: { defaults?: { ease?: string } }) => GsapTimeline;
}

interface PipelineStageTimelineProps {
  jobs: Job[];
}

export function PipelineStageTimeline({ jobs }: PipelineStageTimelineProps) {
  const { policy, strategy } = useMotionPolicy('graph');
  const rootRef = useRef<HTMLDivElement>(null);

  const stageData = useMemo(() => {
    const stageOrder = resolveStageOrder(jobs);
    return stageOrder.map(stage => {
      const active = jobs.filter(job =>
        (job.stage_progress ?? []).some(entry => normalizeStageName(entry.stage) === stage && entry.status === 'running')
      ).length;
      const completed = jobs.filter(job =>
        (job.stage_progress ?? []).some(entry => normalizeStageName(entry.stage) === stage && entry.status === 'completed')
      ).length;
      const errored = jobs.filter(job =>
        (job.stage_progress ?? []).some(entry => normalizeStageName(entry.stage) === stage && entry.status === 'error')
      ).length;

      const percents: number[] = [];
      for (const job of jobs) {
        for (const entry of job.stage_progress ?? []) {
          if (normalizeStageName(entry.stage) === stage && typeof entry.percent === 'number') {
            percents.push(entry.percent);
          }
        }
      }
      const avgPercent = percents.length > 0
        ? Math.round(percents.reduce((a, b) => a + b, 0) / percents.length)
        : Math.min(100, active * 28 + completed * 8);

      return { stage, active, completed, errored, avgPercent };
    });
  }, [jobs]);

  useEffect(() => {
    if (!policy.allowGsap || !rootRef.current) return;
    let cleanup: (() => void) | undefined;
    let cancelled = false;

    void import('gsap')
      .then((mod) => {
        if (!rootRef.current || cancelled) return;
        const typedMod = mod as unknown as { gsap?: unknown; default?: unknown };
        const gsap = (typedMod.gsap ?? typedMod.default) as GsapInstance | undefined;
        if (!gsap) return;
        const nodes = rootRef.current.querySelectorAll('.pipeline-timeline-node');
        const bars = rootRef.current.querySelectorAll('.pipeline-timeline-fill');
        const tl = gsap.timeline({ defaults: { ease: 'power2.out' } });
        tl.fromTo(nodes, { opacity: 0, y: strategy.distance }, { opacity: 1, y: 0, duration: strategy.duration, stagger: strategy.stagger });
        tl.fromTo(bars, { scaleX: 0 }, { scaleX: 1, transformOrigin: 'left center', duration: strategy.duration / 1.2, stagger: strategy.stagger / 2 }, '-=0.28');
        cleanup = () => tl.kill();
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
      cleanup?.();
    };
   
  }, [policy.allowGsap, strategy.distance, strategy.duration, strategy.stagger]);

  return (
    <div ref={rootRef} className="pipeline-timeline" role="list" aria-label="Pipeline stage timeline">
      {stageData.map((item) => (
        <div key={item.stage} className="pipeline-timeline-node" role="listitem" aria-label={`${item.stage.replace(/_/g, ' ')}: ${item.active} active, ${item.completed} complete, ${item.errored} error`}>
          <div className="pipeline-timeline-meta">
            <span className="pipeline-timeline-stage">{item.stage.replace(/_/g, ' ')}</span>
            <span className="pipeline-timeline-counts tabular-nums">
              {item.active} active · {item.completed} complete · {item.errored} error
            </span>
          </div>
          <div
            className="pipeline-timeline-track"
            role="progressbar"
            aria-valuenow={item.avgPercent}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={`${item.stage.replace(/_/g, ' ')} progress`}
          >
            <div
              className="pipeline-timeline-fill"
              style={{ width: `${Math.min(100, item.avgPercent)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
