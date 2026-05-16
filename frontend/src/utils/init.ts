import { dispatchToast } from '@/lib/toastDispatcher';
import { showErrorOverlay } from '@/utils/errorOverlay';

let errorTrackingSetup = false;

export async function clearLegacyServiceWorkers(): Promise<void> {
  if ('serviceWorker' in navigator) {
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(registrations.map(registration => registration.unregister()));
  }

  if ('caches' in window) {
    const cacheNames = await caches.keys();
    await Promise.all(
      cacheNames
        .filter(name => name.startsWith('cyberpipe-'))
        .map(name => caches.delete(name))
    );
  }
}

export function registerServiceWorker(): void {
  void clearLegacyServiceWorkers().catch(error => {
   
    console.warn('[SW] Legacy cleanup failed:', error);
  });
}

export function initWebVitals(): void {
  import('web-vitals').then(({ onCLS, onLCP, onFCP, onTTFB }) => {
    const report = (metric: { name: string; value: number; delta: number }) => {
      if (import.meta.env.DEV) {
   
        console.info(`[WebVitals] ${metric.name}:`, metric.value);
      }
    };
    onCLS(report);
    onLCP(report);
    onFCP(report);
    onTTFB(report);
  }).catch(() => {
    // web-vitals not available
  });
}

// FIX: Idempotency guard — prevent duplicate error listeners
export function setupGlobalErrorTracking(): void {
  if (errorTrackingSetup) return;
  errorTrackingSetup = true;

  window.addEventListener('error', (event) => {
   
    console.error('[GlobalError]', event.error || event.message);

    // Resource loading errors (images, scripts, stylesheets) - capture phase logic moved here
    if (event.target !== window && event.target instanceof Element) {
      const target = event.target;
      const tag = target.tagName;
      if (tag === 'SCRIPT' || tag === 'LINK') {
        showErrorOverlay('Resource Load Error', `Failed to load ${tag}`);
      }
      return;
    }

    dispatchToast(`Runtime Error: ${event.message}`, 'error');
    showErrorOverlay('JavaScript Error', event.error?.message || event.message || 'Unknown error', event.error?.stack);
  }, true); // Use capture phase to catch resource errors too

  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason;
    const message = reason?.message || reason?.toString?.() || '';
    const lowered = String(message).toLowerCase();

    // Request cancellation is expected during route changes and polling cleanup.
    if (
      lowered === 'canceled' ||
      lowered === 'abort' ||
      reason?.name === 'CanceledError' ||
      reason?.name === 'AbortError'
    ) {
      return;
    }

   
    console.error('[UnhandledRejection]', event.reason);
    dispatchToast(`Async Failure: ${message}`, 'error');
    showErrorOverlay('Async Error', message, reason?.stack);
  });
}
