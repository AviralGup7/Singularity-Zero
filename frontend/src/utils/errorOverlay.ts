/** Single overlay entry point. Prefers the React overlay; falls back to DOM. */

export function showErrorOverlay(title: string, message: string, stack?: string) {
  void import('@/components/ui/ErrorOverlayView')
    .then((mod) => {
      mod.showErrorOverlay(title, message, stack);
    })
    .catch(() => {
      showDomFallback(title, message, stack);
    });
}

function showDomFallback(title: string, message: string, stack?: string) {
  if (typeof document === 'undefined') return;
  const existing = document.getElementById('error-overlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  overlay.id = 'error-overlay';
  overlay.className = 'error-overlay';
  const card = document.createElement('div');
  card.className = 'error-overlay-card';
  const header = document.createElement('div');
  header.className = 'error-overlay-header';
  const titleEl = document.createElement('h2');
  titleEl.className = 'error-overlay-title';
  titleEl.textContent = `⚠ ${title}`;
  const closeBtn = document.createElement('button');
  closeBtn.className = 'error-overlay-close';
  closeBtn.textContent = '✕ Close';
  closeBtn.addEventListener('click', () => overlay.remove());
  header.appendChild(titleEl);
  header.appendChild(closeBtn);
  const content = document.createElement('div');
  content.className = 'error-overlay-content';
  const pre = document.createElement('pre');
  pre.className = 'error-overlay-pre';
  pre.textContent = message;
  content.appendChild(pre);
  if (stack && (import.meta.env?.DEV ?? false)) {
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = 'Full stack trace';
    const stackPre = document.createElement('pre');
    stackPre.textContent = stack;
    details.appendChild(summary);
    details.appendChild(stackPre);
    content.appendChild(details);
  }
  card.appendChild(header);
  card.appendChild(content);
  overlay.appendChild(card);
  document.body.appendChild(overlay);
}
