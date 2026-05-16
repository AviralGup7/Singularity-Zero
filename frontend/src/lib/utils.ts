import clsx, { type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function safeGet<V>(obj: Record<string, V>, key: string): V | undefined;
export function safeGet<V>(obj: Record<string, V>, key: string, fallback: V): V;
export function safeGet<V>(obj: Record<string, V>, key: string, fallback?: V): V | undefined {
  // eslint-disable-next-line security/detect-object-injection
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : fallback;
}

export function classifyLogLine(line: string): string {
  const lower = line.toLowerCase();
  if (lower.includes('error') || lower.includes('exception') || lower.includes('fatal') || lower.includes('traceback')) return 'log-line log-error';
  if (lower.includes('warn')) return 'log-line log-warn';
  if (lower.includes('success') || lower.includes('complete') || lower.includes('done')) return 'log-line log-success';
  if (lower.includes('info') || lower.includes('starting') || lower.includes('loading')) return 'log-line log-info';
  return 'log-line';
}

export function getStageIcon(stage: string): string {
  const STAGE_ICONS: Record<string, string> = {
    discovery: '🔍',
    collection: '🕸️',
    analysis: '🧠',
    validation: '✅',
    reporting: '📊',
    complete: '🏁',
    failed: '❌',
    stopped: '⏹️',
  };
  const lower = stage.toLowerCase();
   
  for (const [key, icon] of Object.entries(STAGE_ICONS)) {
    if (lower.includes(key)) return icon;
  }
  return '⚙️';
}

export function calculateHealthScore(
  severityTotals: Record<string, number>
): { score: number; label: string; tone: string } {
   
  const critical = severityTotals['critical'] || 0;
   
  const high = severityTotals['high'] || 0;
   
  const medium = severityTotals['medium'] || 0;
  const score = Math.max(0, 100 - Math.min(100, critical * 15 + high * 8 + medium * 3));
  const label =
    score >= 70 ? 'Healthy' :
    score >= 50 ? 'Moderate Risk' :
    score >= 30 ? 'High Risk' :
    score >= 10 ? 'At Risk' : 'Critical';
  const tone =
    score >= 70 ? 'info' :
    score >= 50 ? 'ok' :
    score >= 30 ? 'warn' : 'bad';
  return { score, label, tone };
}

export function getPageNumbers(currentPage: number, totalPages: number): (number | string)[] {
   
  const pages: (number | string)[] = [];
  const maxVisible = 5;

  if (totalPages <= maxVisible + 2) {
    for (let i = 1; i <= totalPages; i++) pages.push(i);
  } else {
    pages.push(1);
    if (currentPage > 3) pages.push('...');
    const start = Math.max(2, currentPage - 1);
    const end = Math.min(totalPages - 1, currentPage + 1);
    for (let i = start; i <= end; i++) pages.push(i);
    if (currentPage < totalPages - 2) pages.push('...');
    pages.push(totalPages);
  }
  return pages;
}

export function getStatusColor(changed: boolean | null): string {
  if (changed === null) return 'var(--muted)';
  return changed ? 'var(--bad)' : 'var(--ok)';
}

export function getStatusLabel(changed: boolean | null): string {
  if (changed === null) return 'Unknown';
  return changed ? 'Changed' : 'Unchanged';
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
   
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  // eslint-disable-next-line security/detect-object-injection
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function parseUrls(url: string): string[] {
  if (!url) return [];
   
  return url.split(/[,;\n]+/).map(u => u.trim()).filter(Boolean);
}

export function validateUrl(url: string): { valid: boolean; error?: string } {
  if (!url || !url.trim()) return { valid: false, error: 'URL is required' };

   
  const urls = url.split(/[,;\n]+/).map(u => u.trim()).filter(Boolean);

  if (urls.length === 0) return { valid: false, error: 'URL is required' };

  for (const rawUrl of urls) {
    const trimmed = rawUrl.trim();
    if (!trimmed) continue;

    const urlWithProtocol = trimmed.match(/^https?:\/\//) ? trimmed : `https://${trimmed}`;

    try {
      const parsed = new URL(urlWithProtocol);
   
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return { valid: false, error: `Only http:// and https:// protocols are allowed (got: ${trimmed})` };
      }
      const hostname = parsed.hostname.toLowerCase();
      if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0') {
        return { valid: false, error: 'Localhost and loopback addresses are not allowed' };
      }
      if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        return { valid: false, error: 'Private IP ranges (10.x.x.x) are not allowed' };
      }
      if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        return { valid: false, error: 'Private IP ranges (192.168.x.x) are not allowed' };
      }
   
      if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        return { valid: false, error: 'Private IP ranges (172.16-31.x.x) are not allowed' };
      }
      const tld = parsed.hostname.split('.').pop() || '';
   
      if (tld.length < 2 || !/^[a-z]{2,}$/.test(tld)) {
        return { valid: false, error: `URL must have a valid top-level domain (e.g., .com, .org): ${trimmed}` };
      }
    } catch {
      return { valid: false, error: `Invalid URL format: ${trimmed} (e.g., https://example.com)` };
    }
  }

  return { valid: true };
}

export function formatFindingDate(timestamp: number | string | undefined | null): string {
  if (!timestamp) return '—';
  try {
    const date = typeof timestamp === 'number'
      ? new Date(timestamp * (timestamp > 9999999999 ? 1 : 1000))
      : new Date(timestamp);
    return date.toLocaleDateString();
  } catch {
    return '—';
  }
}
