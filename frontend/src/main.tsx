import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './styles/index.css'
import App from '@/App.tsx'

// Auto-recover when stale hashed chunks 404 after a new deploy/build.
window.addEventListener('vite:preloadError', (event) => {
  event.preventDefault();
  window.location.reload();
});

// ============================================
// COMPREHENSIVE ERROR HANDLING (CSP-safe)
// ============================================

function showErrorOverlay(title: string, message: string, stack?: string) {
  const existing = document.getElementById('error-overlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'error-overlay';
  overlay.className = 'error-overlay';

  const card = document.createElement('div');
  card.className = 'error-overlay-card';

  // Header section
  const header = document.createElement('div');
  header.className = 'error-overlay-header';

  const titleEl = document.createElement('h2');
  titleEl.className = 'error-overlay-title';
  titleEl.textContent = `\u26A0\uFE0F ${title}`;

  const closeBtn = document.createElement('button');
  closeBtn.className = 'error-overlay-close';
  closeBtn.textContent = '\u2715 Close';
  closeBtn.addEventListener('click', () => overlay.remove());

  header.appendChild(titleEl);
  header.appendChild(closeBtn);

  // Content section
  const content = document.createElement('div');
  content.className = 'error-overlay-content';

  // Error details box
  const errorBox = document.createElement('div');
  errorBox.className = 'error-overlay-box';

  const errorLabel = document.createElement('p');
  errorLabel.className = 'error-overlay-label';
  errorLabel.textContent = 'Error Details:';

  const errorPre = document.createElement('pre');
  errorPre.className = 'error-overlay-pre';
  errorPre.textContent = message; // Safe: textContent escapes HTML

  errorBox.appendChild(errorLabel);
  errorBox.appendChild(errorPre);
  content.appendChild(errorBox);

  // Stack trace (collapsible)
  if (stack) {
    // SECURITY: Hide stack traces in production to avoid leaking internal paths
    const showStack = import.meta.env?.DEV ?? true;

    if (showStack) {
      const details = document.createElement('details');
      details.className = 'error-overlay-details';

      const summary = document.createElement('summary');
      summary.className = 'error-overlay-summary';
      summary.textContent = '\uD83D\uDCCB Full Stack Trace';

      const stackPre = document.createElement('pre');
      stackPre.className = 'error-overlay-stack';
      stackPre.textContent = stack;

      details.appendChild(summary);
      details.appendChild(stackPre);
      content.appendChild(details);
    }
  }

  // Tip section
  const tip = document.createElement('div');
  tip.className = 'error-overlay-tip';
  tip.textContent = '\uD83D\uDCA1 Tip: Check the browser console (F12) for more details.';
  content.appendChild(tip);

  card.appendChild(header);
  card.appendChild(content);
  overlay.appendChild(card);
  document.body.appendChild(overlay);
}

// Global JavaScript errors (bubbling phase)
window.addEventListener('error', (e) => {
  console.error('Global Error:', e.error || e.message);
  showErrorOverlay(
    'JavaScript Error',
    e.error?.message || e.message || 'Unknown error',
    e.error?.stack
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
    stack
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
    
    // Only show overlay for critical resources that would cause a blank screen
    if (tag === 'SCRIPT' || tag === 'LINK') {
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
    if (root && root.innerHTML === '') {
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

    try {
      const init = await import('@/utils/init');
      setupGlobalErrorTracking = init.setupGlobalErrorTracking;
      registerServiceWorker = init.registerServiceWorker;
      initWebVitals = init.initWebVitals;
    } catch (e) {
      console.warn('Failed to load init utilities:', e);
    }

    // Initialize utilities if available
    setupGlobalErrorTracking?.();
    registerServiceWorker?.();
    initWebVitals?.();

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
      createRoot(rootEl).render(
        <StrictMode>
          <App />
        </StrictMode>,
      );
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
      err instanceof Error ? err.stack : undefined
    );
  }
}

void bootstrap();
