import { useLocation } from 'react-router-dom';
import { useMemo, useState, useEffect } from 'react';
import { getJob } from '@/api/client';
import type { BreadcrumbItem } from '@/components/ui/Breadcrumbs';

function useJobName(jobId: string | undefined) {
   
  const [jobName, setJobName] = useState<string | null>(null);

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    getJob(jobId).then(job => {
      if (!cancelled && job) {
        setJobName(job.target_name || job.id);
      }
    });
    return () => { cancelled = true; };
   
  }, [jobId]);

  return jobName;
}

export function useAutoBreadcrumbs(): BreadcrumbItem[] {
  const location = useLocation();
  const pathname = location.pathname;

  const jobId = pathname.startsWith('/jobs/') ? pathname.replace('/jobs/', '') : undefined;
  const jobName = useJobName(jobId);

  const crumbs = useMemo((): BreadcrumbItem[] => {
    const segments = pathname.split('/').filter(Boolean);

    if (segments.length === 0) return [];

   
    const items: BreadcrumbItem[] = [];

   
    if (segments[0] === 'targets') {
      items.push({
        label: 'Targets',
        href: '/targets',
        isCurrent: segments.length === 1,
      });
   
    } else if (segments[0] === 'jobs') {
      items.push({
        label: 'Jobs',
        href: '/jobs',
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
        href: '/replay',
        isCurrent: true,
      });
   
    } else if (segments[0] === 'settings') {
      items.push({
        label: 'Settings',
        href: '/settings',
        isCurrent: true,
      });
    }

    return items;
   
  }, [pathname, jobName]);

  return crumbs;
}
