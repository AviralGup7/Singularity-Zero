import { useEffect, useMemo, useRef } from 'react';
import type { Job } from '@/types/api';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';

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

const STAGE_ALIASES: Record<string, string> = {
  priority: 'ranking',
};

function normalizeStageName(stageName: string | undefined): string {
  const normalized = String(stageName || '').trim().toLowerCase();
  if (!normalized) return '';
  return STAGE_ALIASES[normalized] ?? normalized;
}

   
function resolveStageOrder(jobs: Job[]): string[] {
   
  const order = [...STAGE_ORDER];
  const seen = new Set(order);

  const addStage = (stageName: string | undefined) => {
    const normalized = normalizeStageName(stageName);
    if (!normalized || seen.has(normalized)) return;
    if (normalized === 'recon_validation') {
      const urlsIndex = order.indexOf('urls');
      if (urlsIndex >= 0) {
        order.splice(urlsIndex + 1, 0, normalized);
      } else {
        order.push(normalized);
      }
      seen.add(normalized);
      return;
    }
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

interface PipelineStageTimelineProps {
  jobs: Job[];
}

export function PipelineStageTimeline({ jobs }: PipelineStageTimelineProps) {
  const { policy, strategy } = useMotionPolicy('graph');
  const rootRef = useRef<HTMLDivElement>(null);

  const stageData = useMemo(() => {
    const stageOrder = resolveStageOrder(jobs);
    return stageOrder.map(stage => {
      const active = jobs.filter(job => normalizeStageName(job.stage) === stage).length;
      const completed = jobs.filter(job =>
        (job.stage_progress ?? []).some(entry => normalizeStageName(entry.stage) === stage && entry.status === 'completed')
      ).length;
      const errored = jobs.filter(job =>
        (job.stage_progress ?? []).some(entry => normalizeStageName(entry.stage) === stage && entry.status === 'error')
      ).length;
      return { stage, active, completed, errored };
    });
   
  }, [jobs]);

  useEffect(() => {
    if (!policy.allowGsap || !rootRef.current) return;
    let cleanup: (() => void) | undefined;
    let cancelled = false;

    void import('gsap')
      .then((mod) => {
        if (!rootRef.current || cancelled) return;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const gsap = (mod as any).gsap ?? (mod as any).default;
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
    <div ref={rootRef} className="pipeline-timeline">
      {stageData.map((item) => (
        <div key={item.stage} className="pipeline-timeline-node">
          <div className="pipeline-timeline-meta">
            <span className="pipeline-timeline-stage">{item.stage.replace(/_/g, ' ')}</span>
            <span className="pipeline-timeline-counts">
              {item.active} active · {item.completed} complete · {item.errored} error
            </span>
          </div>
          <div className="pipeline-timeline-track">
            <div
              className="pipeline-timeline-fill"
              style={{ width: `${Math.min(100, item.active * 28 + item.completed * 8)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
