import type { StageTheaterStatus } from '@/lib/stageTheaterUtils';

export const TREE_LEVELS: string[][] = [
  ['startup'],
  ['subdomains'],
  ['live_hosts'],
  ['urls'],
  ['recon_validation'],
  ['parameters'],
  ['ranking'],
  ['passive_scan'],
  ['active_scan', 'semgrep', 'nuclei', 'access_control'],
  ['validation'],
  ['intelligence'],
  ['reporting'],
];

export const TREE_EDGES: Array<[string, string]> = [
  ['startup', 'subdomains'],
  ['subdomains', 'live_hosts'],
  ['live_hosts', 'urls'],
  ['urls', 'recon_validation'],
  ['recon_validation', 'parameters'],
  ['parameters', 'ranking'],
  ['ranking', 'passive_scan'],
  ['passive_scan', 'active_scan'],
  ['passive_scan', 'semgrep'],
  ['passive_scan', 'nuclei'],
  ['passive_scan', 'access_control'],
  ['active_scan', 'validation'],
  ['passive_scan', 'validation'],
  ['active_scan', 'intelligence'],
  ['nuclei', 'intelligence'],
  ['validation', 'intelligence'],
  ['passive_scan', 'intelligence'],
  ['validation', 'reporting'],
  ['access_control', 'reporting'],
  ['nuclei', 'reporting'],
  ['intelligence', 'reporting'],
];

export const STAGE_ACTIVITY_LABELS: Record<string, string> = {
  startup: 'INITIALIZING',
  subdomains: 'ENUMERATING',
  live_hosts: 'PROBING',
  urls: 'COLLECTING',
  recon_validation: 'VERIFYING RECON',
  parameters: 'MUTATING',
  ranking: 'RANKING',
  passive_scan: 'PASSIVE SWEEP',
  active_scan: 'ACTIVE PROBE',
  semgrep: 'STATIC ANALYSIS',
  nuclei: 'SIGNATURE SCAN',
  access_control: 'ACCESS CHECK',
  validation: 'VALIDATING',
  intelligence: 'CORRELATING',
  reporting: 'COMPILING',
};

export const AMBIENT_LOG_LINES = [
  '[INFO] scanning host batch...',
  '[PASSIVE] collecting endpoints...',
  '[FLOW] stage graph synchronized',
  '[QUEUE] retry monitor online',
  '[TRACE] telemetry stream active',
  '[STATE] processing node transitions',
];

export const NODE_COLORS: Record<StageTheaterStatus, string> = {
  pending: 'var(--muted, #8ea4bf)',
  running: 'var(--accent, #37f6ff)',
  completed: 'var(--ok, #1fe28a)',
  error: 'var(--bad, #ff5568)',
  skipped: 'var(--warn, #ffc74f)',
};
