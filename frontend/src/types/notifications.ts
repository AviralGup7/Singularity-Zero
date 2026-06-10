/** Unified notification types for the frontend.

These types bridge the backend NotificationEvent/Priority enums with the
frontend notification UI. All notification-related code should import from here.
*/

/** Backend event types mapped to frontend-friendly type strings. */
export type NotificationType =
  | 'scan_started'
  | 'scan_completed'
  | 'scan_failed'
  | 'new_finding'
  | 'critical_vulnerability'
  | 'rate_limit_exceeded'
  | 'error'
  | 'pipeline_timeout'
  | 'self_healing_action'
  | 'compliance_violation'
  | 'custom';

/** Severity levels matching backend NotificationPriority. */
export type NotificationSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Core notification interface used by all frontend components. */
export interface AppNotification {
  id: string;
  type: NotificationType;
  severity: NotificationSeverity;
  title: string;
  message: string;
  timestamp: number;
  read: boolean;
  source?: string;
  href?: string;
  entity_id?: string;
  entity_type?: string;
  event?: string;
}

/** API response for paginated notification list. */
export interface NotificationListResponse {
  notifications: Array<{
    id: string;
    event: string;
    priority: string;
    title: string;
    message: string;
    metadata: string;
    source: string;
    correlation_id: string | null;
    entity_id: string | null;
    entity_type: string | null;
    href: string | null;
    read: number;
    created_at: string;
  }>;
  total: number;
  unread_count: number;
  limit: number;
  offset: number;
}

/** SSE notification event pushed from the backend broadcaster. */
export interface NotificationSSEEvent {
  id: string;
  type: NotificationType;
  severity: NotificationSeverity;
  title: string;
  message: string;
  source: string;
  href?: string;
  entity_id?: string;
  entity_type?: string;
  timestamp: number;
  read: boolean;
  event: string;
}

/** Map backend event names to frontend notification types. */
export const EVENT_TYPE_MAP: Record<string, NotificationType> = {
  scan_started: 'scan_started',
  scan_completed: 'scan_completed',
  scan_failed: 'scan_failed',
  finding_detected: 'new_finding',
  critical_vulnerability: 'critical_vulnerability',
  rate_limit_exceeded: 'rate_limit_exceeded',
  system_error: 'error',
  pipeline_timeout: 'pipeline_timeout',
  self_healing_action: 'self_healing_action',
  compliance_violation: 'compliance_violation',
  custom: 'custom',
};

/** Map backend priority to frontend severity. */
export const PRIORITY_SEVERITY_MAP: Record<string, NotificationSeverity> = {
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'critical',
};

/** Severity color tokens for the notification UI. */
export const SEVERITY_COLORS: Record<NotificationSeverity, string> = {
  critical: 'var(--color-danger, #ff3b30)',
  high: 'var(--color-warning, #ff9500)',
  medium: 'var(--color-accent, #00e5ff)',
  low: 'var(--color-success, #34c759)',
  info: 'var(--color-muted, #8e8e93)',
};

/** Icon names for each notification type. */
export const TYPE_ICONS: Record<NotificationType, string> = {
  scan_started: 'activity',
  scan_completed: 'checkCircle',
  scan_failed: 'xCircle',
  new_finding: 'shield',
  critical_vulnerability: 'alertTriangle',
  rate_limit_exceeded: 'clock',
  error: 'alertCircle',
  pipeline_timeout: 'clock',
  self_healing_action: 'zap',
  compliance_violation: 'shieldCheck',
  custom: 'info',
};

/** Human-readable labels for notification types. */
export const TYPE_LABELS: Record<NotificationType, string> = {
  scan_started: 'Scan Started',
  scan_completed: 'Scan Completed',
  scan_failed: 'Scan Failed',
  new_finding: 'New Finding',
  critical_vulnerability: 'Critical Vulnerability',
  rate_limit_exceeded: 'Rate Limit Exceeded',
  error: 'System Error',
  pipeline_timeout: 'Pipeline Timeout',
  self_healing_action: 'Self-Healing Action',
  compliance_violation: 'Compliance Violation',
  custom: 'Notification',
};

/** Convert a backend API notification row to the frontend AppNotification type. */
export function apiNotificationToAppNotification(
  row: NotificationListResponse['notifications'][number]
): AppNotification {
  return {
    id: row.id,
    type: (EVENT_TYPE_MAP[row.event] ?? 'custom') as NotificationType,
    severity: (PRIORITY_SEVERITY_MAP[row.priority] ?? 'info') as NotificationSeverity,
    title: row.title,
    message: row.message,
    timestamp: new Date(row.created_at).getTime(),
    read: row.read === 1,
    source: row.source,
    href: row.href ?? undefined,
    entity_id: row.entity_id ?? undefined,
    entity_type: row.entity_type ?? undefined,
    event: row.event,
  };
}

/** Convert an SSE notification event to AppNotification. */
export function sseEventToAppNotification(event: NotificationSSEEvent): AppNotification {
  return {
    id: event.id,
    type: event.type,
    severity: event.severity,
    title: event.title,
    message: event.message,
    timestamp: event.timestamp,
    read: event.read,
    source: event.source,
    href: event.href,
    entity_id: event.entity_id,
    entity_type: event.entity_type,
    event: event.event,
  };
}
