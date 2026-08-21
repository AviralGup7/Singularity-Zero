import type { JobCard, NotificationCard } from './types';

export function jobTone(job: Pick<JobCard, 'status' | 'stalled' | 'critical_findings'>): 'ok' | 'warn' | 'fail' {
  if (job.status === 'failed' || job.critical_findings > 0) return 'fail';
  if (job.stalled || job.status === 'stopping') return 'warn';
  return 'ok';
}

export function notificationTone(item: Pick<NotificationCard, 'priority' | 'read'>): 'muted' | 'info' | 'alert' {
  if (item.read) return 'muted';
  if (item.priority === 'critical' || item.priority === 'high') return 'alert';
  return 'info';
}

export function progressLabel(job: Pick<JobCard, 'progress_percent' | 'stage_label' | 'status'>): string {
  if (job.status === 'completed') return 'Complete';
  if (job.status === 'failed') return 'Failed';
  if (job.status === 'stopped') return 'Stopped';
  return `${job.stage_label} · ${Math.round(job.progress_percent)}%`;
}

export function unreadCount(items: Array<Pick<NotificationCard, 'read'>>): number {
  return items.reduce((total, item) => total + (item.read ? 0 : 1), 0);
}
