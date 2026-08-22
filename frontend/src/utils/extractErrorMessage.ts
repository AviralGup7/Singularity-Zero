import { dispatchToast } from '../lib/toastDispatcher';

/**
 * Extracts a specific, human-readable error message from any error type.
 * Never returns generic strings like "An error occurred".
 */
export function formatErrorDetail(detail: unknown): string | undefined {
  if (typeof detail === 'string' && detail.trim().length > 0) return detail;
  if (Array.isArray(detail)) {
    const parts = detail.map((item) => {
      if (typeof item === 'string') return item;
      if (item && typeof item === 'object' && 'msg' in item) return String((item as { msg: unknown }).msg ?? '');
      return '';
    }).filter(Boolean);
    return parts.length > 0 ? parts.join('; ') : undefined;
  }
  return undefined;
}

export function extractErrorMessage(err: unknown, fallback?: string): string {
  if (err instanceof Error) {
    const msg = err.message;
    if (msg && msg !== 'Error' && msg !== 'Unexpected error' && msg.trim().length > 0) {
      return msg;
    }
  }

  if (typeof err === 'string' && err.trim().length > 0) {
    return err;
  }

  if (err && typeof err === 'object') {
    const obj = err as Record<string, unknown>;

    if (typeof obj.message === 'string' && obj.message.trim().length > 0) {
      return obj.message;
    }
    const detailText = formatErrorDetail(obj.detail);
    if (detailText) return detailText;
    if (typeof obj.error === 'string' && obj.error.trim().length > 0) {
      return obj.error;
    }
    if (typeof obj.statusText === 'string' && obj.statusText.trim().length > 0) {
      return obj.statusText;
    }

    if (obj.response && typeof obj.response === 'object') {
      const resp = obj.response as Record<string, unknown>;
      if (resp.data && typeof resp.data === 'object') {
        const data = resp.data as Record<string, unknown>;
        const nested = formatErrorDetail(data.detail);
        if (nested) return nested;
        if (typeof data.message === 'string') return data.message;
        if (typeof data.error === 'string') return data.error;
      }
      if (typeof resp.statusText === 'string') return resp.statusText;
    }
  }

  if (fallback) return fallback;
  return 'An unexpected error occurred. Please try again.';
}

/**
 * Shows a toast popup with a specific, non-generic error message.
 * Extracts the real message from the error object.
 */
export function showErrorToast(err: unknown, context?: string): void {
  const message = extractErrorMessage(err);
  const prefix = context ? `${context}: ` : '';
  dispatchToast(`${prefix}${message}`, 'error');
}

/**
 * Shows a toast popup with a specific success message.
 */
export function showSuccessToast(message: string): void {
  dispatchToast(message, 'success');
}

/**
 * Shows a toast popup with a specific warning message.
 */
export function showWarningToast(message: string): void {
  dispatchToast(message, 'warning');
}
