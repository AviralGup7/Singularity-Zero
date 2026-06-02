const TRACKING_PARAM_RE = /^(utm_|fbclid$|gclid$|msclkid$)/i;

/**
 * Normalize URL: lowercase protocol and hostname, strip default ports,
 * remove hash, drop tracking params with deterministic ordering,
 * strip trailing slash (except root).
 */
export function normalizeUrl(input: string): string {
  const withProtocol = input.match(/^https?:\/\//i) ? input : `https://${input}`;
  const parsed = new URL(withProtocol);

  parsed.protocol = parsed.protocol.toLowerCase();
  parsed.hostname = parsed.hostname.toLowerCase();

  if ((parsed.protocol === 'https:' && parsed.port === '443') || (parsed.protocol === 'http:' && parsed.port === '80')) {
    parsed.port = '';
  }

  parsed.hash = '';

  const params = new URLSearchParams(parsed.search);
  const kept: Array<[string, string]> = [];
  params.forEach((value, key) => {
    if (!TRACKING_PARAM_RE.test(key)) {
      kept.push([key, value]);
    }
  });
  kept.sort(([a], [b]) => a.localeCompare(b));
  parsed.search = kept.length > 0 ? `?${new URLSearchParams(kept).toString()}` : '';

  if (parsed.pathname.length > 1) {
    parsed.pathname = parsed.pathname.replace(/\/+$/, '');
  }

  return parsed.toString();
}
