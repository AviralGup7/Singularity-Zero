import { useLocation } from 'react-router-dom';
import { useMemo, useState, useEffect } from 'react';
import { ROUTES } from '@/config/paths';
import { getJob } from '@/api/client';
import type { BreadcrumbItem } from '@/components/ui/Breadcrumbs';
import { showErrorToast } from '@/utils/extractErrorMessage';

export function extractJobIdFromPath(pathname: string, jobsRoot = '/jobs'): string | undefined {
  if (!pathname.startsWith(`${jobsRoot}/`)) return undefined;
  const rest = pathname.slice(jobsRoot.length + 1).split('/')[0] ?? '';
  const id = rest.trim();
  return id || undefined;
}

function useJobName(jobId: string | undefined) {
   
  const [jobName, setJobName] = useState<string | null>(null);

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    getJob(jobId).then(job => {
      if (!cancelled && job) {
        setJobName(job.target_name || job.id);
      }
    }).catch((err) => {
      if (!cancelled) {
        showErrorToast(err, 'Failed to load job name');
      }
    });
    return () => { cancelled = true; };
   
  }, [jobId]);

  return jobName;
}

export function useAutoBreadcrumbs(): BreadcrumbItem[] {
  const location = useLocation();
  const pathname = location.pathname;

  const jobId = extractJobIdFromPath(pathname);
  const jobName = useJobName(jobId);

  const crumbs = useMemo((): BreadcrumbItem[] => {
    const segments = pathname.split('/').filter(Boolean);

    if (segments.length === 0) return [];

    const items: BreadcrumbItem[] = [];

    if (segments[0] === 'targets') {
      items.push({
        label: 'Targets',
        href: ROUTES.TARGETS,
        isCurrent: segments.length === 1,
      });
    } else if (segments[0] === 'jobs') {
      items.push({
        label: 'Jobs',
        href: ROUTES.JOBS,
        isCurrent: segments.length === 1,
      });
      if (segments.length > 1 && jobName) {
        items.push({
          label: jobName,
          isCurrent: true,
        });
      }
    } else if (segments[0] === 'replay') {
      items.push({
        label: 'Replay',
        href: ROUTES.REPLAY,
        isCurrent: true,
      });
    } else if (segments[0] === 'settings') {
      items.push({
        label: 'Settings',
        href: ROUTES.SETTINGS,
        isCurrent: true,
      });
    } else if (segments[0] === 'findings') {
      items.push({
        label: 'Findings',
        href: ROUTES.FINDINGS,
        isCurrent: true,
      });
    } else if (segments[0] === 'pipeline') {
      items.push({
        label: 'Pipeline',
        href: ROUTES.PIPELINE,
        isCurrent: true,
      });
    } else if (segments[0] === 'cockpit') {
      items.push({
        label: 'Cockpit',
        href: ROUTES.COCKPIT,
        isCurrent: true,
      });
    } else if (segments[0] === 'risk') {
      items.push({
        label: 'Risk',
        href: ROUTES.RISK_HUB,
        isCurrent: true,
      });
    } else if (segments[0] === 'governance') {
      items.push({
        label: 'Governance',
        href: ROUTES.GOVERNANCE_HUB,
        isCurrent: true,
      });
    } else if (segments[0] === 'detection-quality') {
      items.push({
        label: 'Detection Quality',
        href: ROUTES.DETECTION_QUALITY,
        isCurrent: true,
      });
    } else if (segments[0] === 'reports') {
      items.push({
        label: 'Reports',
        href: ROUTES.REPORTS,
        isCurrent: segments.length === 1,
      });
      if (segments.length > 1) {
        items.push({
          label: segments.slice(1).join(' / '),
          isCurrent: true,
        });
      }
    } else if (segments[0] === 'security') {
      items.push({
        label: 'Security',
        href: ROUTES.SECURITY,
        isCurrent: true,
      });
    }

    return items;
  }, [pathname, jobName]);

  return crumbs;
}
