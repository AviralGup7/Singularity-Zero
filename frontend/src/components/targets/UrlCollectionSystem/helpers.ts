export type UrlCollectionStatus = 'new' | 'queued' | 'running' | 'started' | 'failed';
export type CollectionSource = 'manual' | 'file';

export interface UrlCollectionItem {
  id: string;
  url: string;
  hostname: string;
  status: UrlCollectionStatus;
  addedAt: string;
  source: CollectionSource;
  lastJobId?: string;
  processedAt?: string;
  processingProfile?: 'quick' | 'full';
  errorMessage?: string;
}

export interface ImportReport {
  added: number;
  duplicates: number;
  invalid: string[];
}

export const STORAGE_KEY = 'targets-url-collection-v1';
const TRACKING_PARAM_RE = /^(utm_|fbclid$|gclid$|msclkid$)/i;
const STATIC_ASSET_RE = /\.(?:png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|ttf|eot|pdf)$/i;

export function isStaticAsset(pathname: string): boolean {
  return STATIC_ASSET_RE.test(pathname);
}

export function normalizeCollectedUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) throw new Error('Empty URL');
  const withProtocol = trimmed.match(/^https?:\/\//i) ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(withProtocol);
  } catch { throw new Error(`Invalid URL: ${trimmed}`); }

  parsed.protocol = parsed.protocol.toLowerCase();
  parsed.hostname = parsed.hostname.toLowerCase();
  if ((parsed.protocol === 'https:' && parsed.port === '443') || (parsed.protocol === 'http:' && parsed.port === '80')) {
    parsed.port = '';
  }
  parsed.hash = '';

  const params = new URLSearchParams(parsed.search);
  const kept: Array<[string, string]> = [];
  params.forEach((value, key) => {
    if (!TRACKING_PARAM_RE.test(key)) kept.push([key, value]);
  });
  kept.sort(([a], [b]) => a.localeCompare(b));
  parsed.search = kept.length > 0 ? `?${new URLSearchParams(kept).toString()}` : '';

  if (parsed.pathname.length > 1) {
    parsed.pathname = parsed.pathname.replace(/\/+$/, '');
  }
  return parsed.toString();
}

export function statusTone(status: UrlCollectionStatus): string {
  switch (status) {
    case 'started': return 'ok';
    case 'failed': return 'bad';
    case 'running': return 'accent';
    default: return 'muted';
  }
}

export function createCollectionId(): string {
  return `url-${crypto.randomUUID()}`;
}

export function createLocalJobId(hostname: string, mode: 'quick' | 'full'): string {
  const safeHost = hostname.replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, 12) || 'target';
  return `local-${mode}-${safeHost}-${crypto.randomUUID()}`;
}

export function statusLabel(status: UrlCollectionStatus): string {
  const labels: Record<UrlCollectionStatus, string> = {
    new: 'New', queued: 'Queued', running: 'Running', started: 'Started', failed: 'Failed',
  };
  return labels[status];
}
