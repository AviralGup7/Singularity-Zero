/**
 * Shared toast dispatcher for non-React contexts (e.g., API interceptors).
 * The ToastProvider sets this function on mount, replacing the need for
 * CustomEvent dispatching which creates race conditions.
 */

type ToastType = 'success' | 'error' | 'warning' | 'info';

let toastFn: ((message: string, type: ToastType) => void) | null = null;

export function setToastDispatcher(fn: (message: string, type: ToastType) => void) {
  toastFn = fn;
}

export function dispatchToast(message: string, type: ToastType) {
  if (toastFn) {
    toastFn(message, type);
  } else {
    // Fallback to console if ToastProvider is not mounted yet
    // Security: in production, do not expose error details to console
    if (import.meta.env.DEV) {
   
      console.warn('[Toast] ToastProvider not mounted. Toast:', message);
    }
  }
}
