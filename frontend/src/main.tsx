import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './styles/index.css'
import App from '@/App.tsx'
import { showErrorOverlay } from '@/utils/errorOverlay'

// Auto-recover when stale hashed chunks 404 after a new deploy/build.
window.addEventListener('vite:preloadError', (event) => {
  event.preventDefault();
  window.location.reload();
});

// ============================================
// COMPREHENSIVE ERROR HANDLING (CSP-safe)
// ============================================
// NOTE: Duplicate error listeners in init.ts are now guarded by an
// idempotency flag (setupGlobalErrorTracking). The listeners here
// handle boot-time errors BEFORE the React tree mounts; the init.ts
// listeners take over after mount for runtime errors.

// Global JavaScript errors (bubbling phase)
window.addEventListener('error', (e) => {
  const error = e.error || new Error(e.message);
  const message = error.message || '';
  const lowered = String(message).toLowerCase();

  // Ignore request cancellation errors — these are normal during navigation/unmount
  if (
    lowered === 'canceled' ||
    lowered === 'abort' ||
    error.name === 'CanceledError' ||
    error.name === 'AbortError'
  ) {
    e.preventDefault();
    return;
  }

  console.error('Global Error:', error);
  showErrorOverlay(
    'JavaScript Error',
    error.message || 'Unknown error',
    import.meta.env.DEV ? error.stack : undefined,
  );
});

// Unhandled promise rejections
window.addEventListener('unhandledrejection', (e) => {
  // Ignore request cancellation errors — these are normal during navigation
  const reason = e.reason;
  const message = reason?.message || reason?.toString() || '';
  if (message === 'canceled' || message === 'abort' || reason?.name === 'CanceledError' || reason?.name === 'AbortError') {
    e.preventDefault();
    return; // Silently ignore
  }

  console.error('Unhandled Promise Rejection:', e.reason);
  const msg = reason?.message || message || 'Unknown promise rejection';
  const stack = reason?.stack;
  showErrorOverlay(
    'Async Error',
    msg,
    import.meta.env.DEV ? stack : undefined,
  );
});

// Resource loading errors (images, scripts, stylesheets) - capture phase
window.addEventListener('error', (e) => {
  if (e.target !== window) {
    const target = e.target as Element;
    const tag = target.tagName;
    const src = (target instanceof HTMLImageElement ? target.src :
                 target instanceof HTMLLinkElement ? (target as HTMLLinkElement).href :
                 target instanceof HTMLScriptElement ? (target as HTMLScriptElement).src :
                 'unknown');
    console.warn(`Failed to load resource: ${tag} - ${src}`);

    // Hosted previews inject analytics (Cloudflare Insights, etc.) that 404
    // in sandboxed iframes. Never block the app for third-party beacons.
    const thirdParty = /cloudflareinsights|cloudflare\.com|google-analytics|googletagmanager|gtag\/js|doubleclick|facebook\.net|hotjar|sentry\.io|newrelic/i;
    if (thirdParty.test(src)) return;

    let sameOrigin = false;
    try {
      sameOrigin = new URL(src, window.location.href).origin === window.location.origin;
    } catch {
      sameOrigin = false;
    }

    if ((tag === 'SCRIPT' || tag === 'LINK') && sameOrigin) {
      showErrorOverlay(
        'Resource Load Error',
        `Failed to load ${tag}: ${src}`,
      );
    }
  }
}, true);

// Try to import init utilities and start the app
async function bootstrap() {
  const bootTimeout = setTimeout(() => {
    const root = document.getElementById('root');
    if (root && !root.hasChildNodes()) {
      showErrorOverlay(
        'Boot Timeout',
        'The application script loaded but failed to mount within 5 seconds. This often indicates a silent crash in a Provider or a blocked dependency. Check the browser console for details.'
      );
    }
  }, 5000);

  try {
    let setupGlobalErrorTracking: (() => void) | undefined;
    let registerServiceWorker: (() => void) | undefined;
    let initWebVitals: (() => void) | undefined;
    let initTimeSync: (() => void) | undefined;

    try {
      const init = await import('@/utils/init');
      setupGlobalErrorTracking = init.setupGlobalErrorTracking;
      registerServiceWorker = init.registerServiceWorker;
      initWebVitals = init.initWebVitals;
      initTimeSync = init.initTimeSync;
    } catch (e) {
      console.warn('Failed to load init utilities:', e);
    }

    // Initialize utilities if available
    setupGlobalErrorTracking?.();
    registerServiceWorker?.();
    // Defer non-critical telemetry to avoid competing with paint
    if (typeof window.requestIdleCallback === 'function') {
      requestIdleCallback(() => initWebVitals?.(), { timeout: 3000 });
      requestIdleCallback(() => initTimeSync?.(), { timeout: 3000 });
    } else {
      initWebVitals?.();
      initTimeSync?.();
    }

    // Ensure i18n is at least attempted before mount
    try {
      const { i18nPromise } = await import('@/i18n');
      await Promise.race([
        i18nPromise,
        new Promise((resolve) => setTimeout(resolve, 2000)) // Don't block forever
      ]);
    } catch (e) {
      console.warn('i18n sync failed or timed out:', e);
    }

    const rootEl = document.getElementById('root');
    if (rootEl) {
      if (typeof performance !== 'undefined' && typeof performance.mark === 'function') {
        performance.mark('app-mount');
      }
      createRoot(rootEl).render(
        <StrictMode>
          <App />
        </StrictMode>,
      );
      if (typeof performance !== 'undefined' && typeof performance.measure === 'function') {
        performance.measure('app-mount-to-ready', 'app-mount');
        const measure = performance.getEntriesByName('app-mount-to-ready')[0];
        if (measure) {
          if (import.meta.env.DEV) console.info('[Performance] App mount-to-ready duration:', measure.duration.toFixed(2), 'ms');
        }
        performance.clearMarks('app-mount');
        performance.clearMeasures('app-mount-to-ready');
        performance.mark('app-ready');
      }
      clearTimeout(bootTimeout);
    } else {
      clearTimeout(bootTimeout);
      showErrorOverlay('Root Element Missing', 'Could not find <div id="root"> in the HTML. The page structure may be incorrect.');
    }
  } catch (err) {
    clearTimeout(bootTimeout);
    console.error('Fatal Bootstrap Error:', err);
    showErrorOverlay(
      'Fatal Bootstrap Error',
      err instanceof Error ? err.message : String(err),
      import.meta.env.DEV && err instanceof Error ? err.stack : undefined,
    );
  }
}

void bootstrap().catch((err) => {
  console.error('Fatal Bootstrap Error:', err);
  showErrorOverlay(
    'Fatal Bootstrap Error',
    err instanceof Error ? err.message : String(err),
    import.meta.env.DEV && err instanceof Error ? err.stack : undefined,
  );
});
