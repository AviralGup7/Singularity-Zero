export type ConsoleAuthMode = 'public' | 'session' | 'demo_ok' | 'bearer';

export type ConsoleCommandName =
  | 'handshake.open'
  | 'handshake.ping'
  | 'handshake.close'
  | 'session.demo_sign_in'
  | 'session.describe'
  | 'session.revoke'
  | 'jobs.list'
  | 'jobs.get'
  | 'jobs.start'
  | 'jobs.stop'
  | 'jobs.events'
  | 'jobs.summaries'
  | 'notifications.list'
  | 'notifications.mark_read'
  | 'notifications.mark_all_read'
  | 'notifications.delete'
  | 'notifications.policy'
  | 'intel.lookup'
  | 'intel.seed'
  | 'snapshot.get'
  | 'stream.poll'
  | 'batch.execute';

export interface CommandSpec {
  name: ConsoleCommandName;
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  path: string;
  auth: ConsoleAuthMode;
  capability: string | null;
  description: string;
  stream?: boolean;
}

export interface ConsoleSession {
  kind: 'demo' | 'guest' | 'api_key' | 'jwt';
  subject: string;
  role: string;
  capabilities: string[];
  has_bearer_token: boolean;
  demo?: boolean;
}

export interface TransportHints {
  use_console_channel: boolean;
  skip_jwt_notifications: boolean;
  skip_jwt_notification_stream: boolean;
  demo_or_guest: boolean;
  has_bearer_token: boolean;
  fetch_notifications_http?: boolean;
  open_notification_stream?: boolean;
  use_console_inbox?: boolean;
  reason?: string;
}

export interface BridgeErrorBody {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface RequestEnvelope {
  command: ConsoleCommandName;
  payload: Record<string, unknown>;
  request_id: string;
  idempotency_key?: string;
  subject?: string;
  bearer_token?: string;
  connection_id?: string;
  path_params?: Record<string, string>;
  query?: Record<string, unknown>;
  protocol: string;
}

export interface ResponseEnvelope<T = Record<string, unknown>> {
  ok: boolean;
  command: string;
  request_id: string;
  status: number;
  data: T;
  error?: BridgeErrorBody;
  events?: Array<Record<string, unknown>>;
  skipped?: boolean;
  protocol: string;
}

export interface JobCard {
  id: string;
  base_url: string;
  hostname: string;
  target_name: string;
  mode: string;
  status: string;
  stage: string;
  stage_label: string;
  status_message: string;
  progress_percent: number;
  elapsed_label: string;
  eta_label: string;
  stalled: boolean;
  findings_count: number;
  critical_findings: number;
  error: string;
  failed_stage: string;
  stop_requested: boolean;
}

export interface NotificationCard {
  id: string;
  title: string;
  message: string;
  event: string;
  priority: string;
  source: string;
  read: boolean;
  href?: string | null;
  entity_id?: string | null;
  created_at: number;
}
