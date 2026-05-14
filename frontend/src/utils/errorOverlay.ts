// ============================================
// COMPREHENSIVE ERROR OVERLAY (XSS-safe)
// ============================================

export function showErrorOverlay(title: string, message: string, stack?: string) {
  if (typeof document === 'undefined') return;

  const existing = document.getElementById('error-overlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'error-overlay';
  overlay.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.85); z-index: 99999;
    display: flex; align-items: center; justify-content: center;
    padding: 2rem; overflow: auto;
  `;

  // Header section
  const header = document.createElement('div');
  header.style.cssText = `
    padding: 1rem 1.5rem; border-bottom: 1px solid #30363d;
    display: flex; align-items: center; justify-content: space-between;
  `;

  const titleEl = document.createElement('h2');
  titleEl.style.cssText = 'color: #f85149; margin: 0; font-size: 1.1rem;';
  titleEl.textContent = `\u26A0\uFE0F ${title}`;

  const closeBtn = document.createElement('button');
  closeBtn.textContent = '\u2715 Close';
  closeBtn.style.cssText = `
    background: #21262d; border: 1px solid #30363d; color: #8b949e;
    padding: 0.25rem 0.75rem; border-radius: 4px; cursor: pointer;
  `;
  closeBtn.addEventListener('click', () => overlay.remove());

  header.appendChild(titleEl);
  header.appendChild(closeBtn);

  // Content section
  const content = document.createElement('div');
  content.style.cssText = 'padding: 1.5rem;';

  // Error details box
  const errorBox = document.createElement('div');
  errorBox.style.cssText = `
    background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    padding: 1rem; margin-bottom: 1rem;
  `;

  const errorLabel = document.createElement('p');
  errorLabel.style.cssText = 'color: #f85149; margin: 0 0 0.5rem; font-weight: 600;';
  errorLabel.textContent = 'Error Details:';

  const errorPre = document.createElement('pre');
  errorPre.style.cssText = `
    color: #c9d1d9; margin: 0; font-size: 0.85rem;
    white-space: pre-wrap; word-break: break-word;
    font-family: 'Consolas', 'Monaco', monospace;
  `;
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
      details.style.marginTop = '1rem';

      const summary = document.createElement('summary');
      summary.style.cssText = 'color: #8b949e; cursor: pointer; font-size: 0.85rem; padding: 0.5rem 0;';
      summary.textContent = '\uD83D\uDCCB Full Stack Trace';

      const stackPre = document.createElement('pre');
      stackPre.style.cssText = `
        background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
        padding: 1rem; color: #6e7681; font-size: 0.75rem;
        white-space: pre-wrap; word-break: break-word;
        font-family: 'Consolas', 'Monaco', monospace;
        max-height: 300px; overflow: auto;
      `;
      stackPre.textContent = stack;

      details.appendChild(summary);
      details.appendChild(stackPre);
      content.appendChild(details);
    }
  }

  // Tip section
  const tip = document.createElement('div');
  tip.style.cssText = 'margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #30363d;';
  const tipText = document.createElement('p');
  tipText.style.cssText = 'color: #8b949e; font-size: 0.8rem; margin: 0;';
  tipText.textContent = '\uD83D\uDCA1 Tip: Check the browser console (F12) for more details.';
  tip.appendChild(tipText);
  content.appendChild(tip);

  // Card container
  const card = document.createElement('div');
  card.style.cssText = `
    background: #161b22; border: 1px solid #f85149; border-radius: 8px;
    max-width: 800px; width: 100%; max-height: 90vh; overflow: auto;
    box-shadow: 0 0 40px rgba(248,81,73,0.3);
  `;
  card.appendChild(header);
  card.appendChild(content);

  overlay.appendChild(card);
  document.body.appendChild(overlay);
}
