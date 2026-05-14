export const SEVERITY_COLORS = {
  critical: 'var(--severity-critical)',
  high: 'var(--severity-high)',
  medium: 'var(--severity-medium)',
  low: 'var(--severity-low)',
  info: 'var(--severity-info)',
} as const;

export const SEVERITY_CLASSES = {
  critical: 'sev critical',
  high: 'sev high',
  medium: 'sev medium',
  low: 'sev low',
  info: 'sev info',
} as const;

export const STATUS_COLORS = {
  running: 'var(--ok)',
  completed: 'var(--accent)',
  failed: 'var(--bad)',
  stopped: 'var(--warn)',
} as const;

export const STATUS_CLASSES = {
  running: 'job-status running',
  completed: 'job-status completed',
  failed: 'job-status failed',
  stopped: 'job-status stopped',
} as const;

export const SPACING = {
  xs: '4px',
  sm: '8px',
  md: '12px',
  lg: '16px',
  xl: '20px',
  '2xl': '24px',
  '3xl': '32px',
} as const;

export const FONT_SIZES = {
  xxs: '0.65rem',
  xs: '0.7rem',
  sm: '0.75rem',
  md: '0.8rem',
  base: '0.85rem',
  lg: '0.9rem',
  xl: '1rem',
  '2xl': '1.2rem',
} as const;

export const COLORS = {
  bg: 'var(--bg)',
  bg2: 'var(--bg-2)',
  panel: 'var(--panel)',
  panel2: 'var(--panel-2)',
  panel3: 'var(--panel-3)',
  text: 'var(--text)',
  muted: 'var(--muted)',
  accent: 'var(--accent)',
  accentHover: 'var(--accent-hover)',
  accentVibrant: 'var(--accent-vibrant)',
  accent2: 'var(--accent-2)',
  ok: 'var(--ok)',
  warn: 'var(--warn)',
  bad: 'var(--bad)',
  line: 'var(--line)',
  inputBg: 'var(--input-bg)',
  hoverBg: 'var(--hover-bg)',
  moduleBg: 'var(--module-bg)',
  errorBg: 'var(--error-bg)',
  errorBorder: 'var(--error-border)',
  warnBg: 'var(--warn-bg)',
  infoBg: 'var(--info-bg)',
  okBg: 'var(--ok-bg)',
  kbdBg: 'var(--kbd-bg)',
  kbdBorder: 'var(--kbd-border)',
  progressBg: 'var(--progress-bg)',
  tableHeaderBg: 'var(--table-header-bg)',
  tableRowHover: 'var(--table-row-hover)',
  tableBorder: 'var(--table-border)',
  modalOverlay: 'var(--modal-overlay)',
  logsBg: 'var(--logs-bg)',
} as const;

export const SHADOWS = {
  card: 'var(--shadow)',
  cardHover: 'var(--card-hover-shadow)',
} as const;

export const FONT_FAMILIES = {
  mono: "'Share Tech Mono', monospace",
  sans: "'Rajdhani', sans-serif",
} as const;

export const TRANSITIONS = {
  default: 'all 0.2s ease',
  height: 'height 0.3s ease',
} as const;
