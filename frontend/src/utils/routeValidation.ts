const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC_ID_REGEX = /^\d+$/;
const SAFE_PATH_REGEX = /^[a-zA-Z0-9_\-]+$/;

export function isValidUUID(value: string): boolean {
  return UUID_REGEX.test(value);
}

export function isValidNumericId(value: string): boolean {
  return NUMERIC_ID_REGEX.test(value) && value.length <= 20;
}

export function isValidRouteParam(value: string): boolean {
  if (!value || value.length > 500) return false;
  return SAFE_PATH_REGEX.test(value);
}

export function sanitizeRedirectPath(path: string): string {
  if (!path) return '/';
  const decoded = decodeURIComponent(path);
  if (decoded.startsWith('//') || decoded.includes('://') || decoded.includes('\\')) {
    return '/';
  }
  if (!decoded.startsWith('/')) return '/';
  const cleaned = decoded.replace(/\/+/g, '/');
  const segments = cleaned.split('/').filter(Boolean);
  const safeSegments = segments.filter(seg => !seg.startsWith('.') && SAFE_PATH_REGEX.test(seg));
  return '/' + safeSegments.join('/');
}

export function isExternalUrl(url: string): boolean {
  try {
    const parsed = new URL(url, window.location.origin);
    return parsed.hostname !== window.location.hostname;
  } catch {
    return false;
  }
}

export function validateJobId(id: string | undefined): string | null {
  if (!id) return null;
  if (isValidUUID(id) || isValidNumericId(id)) return id;
  return null;
}

export function validateEvidenceId(id: string | undefined): string | null {
  if (!id) return null;
  if (isValidUUID(id)) return id;
  return null;
}
