import type { CommandSpec, ConsoleCommandName } from './types';

/** Keep in sync with src/integration/commands.py CATALOG. */
export const PROTOCOL_VERSION = '1.0';
export const HTTP_PREFIX = '/api/console';
export const REQUEST_ID_HEADER = 'X-Request-ID';
export const CONNECTION_HEADER = 'X-Console-Connection';
export const SUBJECT_HEADER = 'X-Console-Subject';
export const PROTOCOL_HEADER = 'X-Console-Protocol';
export const IDEMPOTENCY_HEADER = 'Idempotency-Key';

export const CATALOG: CommandSpec[] = [
  {
    name: 'handshake.open',
    method: 'POST',
    path: '/api/console/handshake',
    auth: 'public',
    capability: null,
    description: 'Open a console connection and negotiate protocol + session.',
  },
  {
    name: 'handshake.ping',
    method: 'POST',
    path: '/api/console/ping',
    auth: 'public',
    capability: null,
    description: 'Keep-alive; refreshes connection last-seen.',
  },
  {
    name: 'handshake.close',
    method: 'POST',
    path: '/api/console/close',
    auth: 'session',
    capability: null,
    description: 'Drop the console connection.',
  },
  {
    name: 'session.demo_sign_in',
    method: 'POST',
    path: '/api/console/session/demo',
    auth: 'public',
    capability: null,
    description: 'Issue a demo session (name + role, no JWT).',
  },
  {
    name: 'session.describe',
    method: 'GET',
    path: '/api/console/session',
    auth: 'session',
    capability: null,
    description: 'Describe the current session and capabilities.',
  },
  {
    name: 'session.revoke',
    method: 'POST',
    path: '/api/console/session/revoke',
    auth: 'session',
    capability: null,
    description: 'Revoke the current session.',
  },
  {
    name: 'jobs.list',
    method: 'GET',
    path: '/api/console/jobs',
    auth: 'session',
    capability: 'viewJobs',
    description: 'List jobs with optional filters.',
  },
  {
    name: 'jobs.get',
    method: 'GET',
    path: '/api/console/jobs/{id}',
    auth: 'session',
    capability: 'viewJobs',
    description: 'Fetch one job card.',
  },
  {
    name: 'jobs.start',
    method: 'POST',
    path: '/api/console/jobs',
    auth: 'session',
    capability: 'launchJobs',
    description: 'Start a simulated or queued scan.',
  },
  {
    name: 'jobs.stop',
    method: 'POST',
    path: '/api/console/jobs/{id}/stop',
    auth: 'session',
    capability: 'stopJobs',
    description: 'Request a cooperative stop.',
  },
  {
    name: 'jobs.events',
    method: 'GET',
    path: '/api/console/jobs/{id}/events',
    auth: 'session',
    capability: 'viewJobs',
    description: 'Job domain events for the timeline.',
  },
  {
    name: 'jobs.summaries',
    method: 'GET',
    path: '/api/console/jobs/summaries',
    auth: 'session',
    capability: 'viewJobs',
    description: 'Operator summaries used by the cockpit strip.',
  },
  {
    name: 'notifications.list',
    method: 'GET',
    path: '/api/console/notifications',
    auth: 'demo_ok',
    capability: null,
    description: 'List inbox items without requiring a JWT.',
  },
  {
    name: 'notifications.mark_read',
    method: 'PATCH',
    path: '/api/console/notifications/{id}/read',
    auth: 'demo_ok',
    capability: null,
    description: 'Mark one notification read.',
  },
  {
    name: 'notifications.mark_all_read',
    method: 'PATCH',
    path: '/api/console/notifications/read-all',
    auth: 'demo_ok',
    capability: null,
    description: 'Mark the inbox read.',
  },
  {
    name: 'notifications.delete',
    method: 'DELETE',
    path: '/api/console/notifications/{id}',
    auth: 'demo_ok',
    capability: null,
    description: 'Dismiss one notification.',
  },
  {
    name: 'notifications.policy',
    method: 'GET',
    path: '/api/console/notifications/policy',
    auth: 'public',
    capability: null,
    description: 'Tell the UI whether JWT notification HTTP/SSE is allowed.',
  },
  {
    name: 'intel.lookup',
    method: 'GET',
    path: '/api/console/intel',
    auth: 'session',
    capability: 'viewFindings',
    description: 'Look up an indicator across seeded feeds.',
  },
  {
    name: 'intel.seed',
    method: 'POST',
    path: '/api/console/intel',
    auth: 'session',
    capability: 'launchJobs',
    description: 'Seed a manual intel vote (offline aggregator).',
  },
  {
    name: 'snapshot.get',
    method: 'GET',
    path: '/api/console/snapshot',
    auth: 'session',
    capability: null,
    description: 'Operator snapshot: jobs + inbox + sessions.',
  },
  {
    name: 'stream.poll',
    method: 'GET',
    path: '/api/console/stream',
    auth: 'demo_ok',
    capability: null,
    description: 'Poll queued connection events (SSE stand-in for demo).',
    stream: true,
  },
  {
    name: 'batch.execute',
    method: 'POST',
    path: '/api/console/batch',
    auth: 'session',
    capability: null,
    description: 'Execute several commands in one round trip.',
  },
];

const BY_NAME = new Map(CATALOG.map((spec) => [spec.name, spec]));

export function getCommand(name: ConsoleCommandName): CommandSpec {
  const spec = BY_NAME.get(name);
  if (!spec) {
    throw new Error(`unknown console command: ${name}`);
  }
  return spec;
}

export function fillPath(path: string, params?: Record<string, string>): string {
  if (!params) return path;
  return path.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, key: string) => {
    const value = params[key];
    if (!value) {
      throw new Error(`missing path param ${key}`);
    }
    return encodeURIComponent(value);
  });
}

export const JWT_NOTIFICATION_PATHS = ['/api/notifications', '/api/notifications/stream'] as const;
