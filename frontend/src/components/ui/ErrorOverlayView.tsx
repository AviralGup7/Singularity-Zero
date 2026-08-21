import { useLayoutEffect, useState } from 'react';
import { createRoot  } from 'react-dom/client';
import { shouldShowErrorStack } from '@/utils/errorOverlayPolicy';
import type {Root} from 'react-dom/client';

let errorRoot: Root | null = null;
let currentOverlay: HTMLDivElement | null = null;

function ensureOverlayRoot() {
  if (typeof document === 'undefined') return null;
  let existing = document.getElementById('error-overlay-root');
  if (!existing) {
    existing = document.createElement('div');
    existing.id = 'error-overlay-root';
    existing.style.cssText = 'position:fixed;inset:0;z-index:2147483647;pointer-events:none;';
    document.body.appendChild(existing);
  }
  if (!errorRoot) {
    errorRoot = createRoot(existing);
  }
  return existing;
}

function removeOverlayRoot() {
  if (currentOverlay && currentOverlay.parentNode) {
    currentOverlay.parentNode.removeChild(currentOverlay);
    currentOverlay = null;
  }
  if (errorRoot) {
    errorRoot.unmount();
    errorRoot = null;
  }
  const root = document.getElementById('error-overlay-root');
  if (root && root.parentNode) root.parentNode.removeChild(root);
}

export function showErrorOverlay(title: string, message: string, stack?: string) {
  if (typeof document === 'undefined') return;
  const node = ensureOverlayRoot();
  if (!node || !errorRoot) return;
  errorRoot.render(<ErrorOverlay title={title} message={message} stack={stack} />);
}

export function ErrorOverlay({ title, message, stack }: { title: string; message: string; stack?: string }) {
  const [visible, setVisible] = useState(true);

  useLayoutEffect(() => {
    const node = ensureOverlayRoot();
    if (!node) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setVisible(true);
  }, [title, message, stack]);

  if (!visible) return null;

  return (
    <div
      role="alert"
      aria-live="assertive"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'var(--modal-overlay)',
        zIndex: 2147483647,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '2rem',
        pointerEvents: 'auto',
      }}
      onContextMenu={(event) => event.preventDefault()}
    >
      <div
        style={{
          background: 'var(--surface-2)',
          border: '1px solid var(--bad)',
          borderRadius: 8,
          maxWidth: 800,
          width: '100%',
          maxHeight: '90vh',
          overflow: 'auto',
          boxShadow: '0 0 40px color-mix(in srgb, var(--bad) 30%, transparent)',
        }}
      >
        <div
          style={{
            padding: '1rem 1.5rem',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <h2 className="text-bad text-lg">⚠️ {title}</h2>
          <button
            type="button"
            onClick={() => {
              removeOverlayRoot();
            }}
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--border)',
              color: 'var(--text-secondary)',
              padding: '0.25rem 0.75rem',
              borderRadius: 4,
              cursor: 'pointer',
            }}
          >
            ✕ Close
          </button>
        </div>
        <div style={{ padding: '1.5rem' }}>
          <div
            style={{
              background: 'var(--surface-muted)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              padding: '1rem',
              marginBottom: '1rem',
            }}
          >
            <p className="text-bad mb-2 font-semibold">Error Details:</p>
            <pre
              style={{
                color: 'var(--text-primary)',
                margin: 0,
                fontSize: '0.85rem',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontFamily: "'Consolas', 'Monaco', monospace",
              }}
            >
              {message}
            </pre>
          </div>
          {shouldShowErrorStack(Boolean(import.meta.env?.DEV), stack) ? (
            <details style={{ marginTop: '1rem' }}>
              <summary
                style={{
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: '0.85rem',
                  padding: '0.5rem 0',
                }}
              >
                📋 Full Stack Trace
              </summary>
              <pre
                style={{
                  background: 'var(--surface-muted)',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  padding: '1rem',
                  color: 'var(--text-tertiary)',
                  fontSize: '0.75rem',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  fontFamily: "'Consolas', 'Monaco', monospace",
                  maxHeight: 300,
                  overflow: 'auto',
                }}
              >
                {stack}
              </pre>
            </details>
          ) : null}
          <div
            style={{
              marginTop: '1rem',
              paddingTop: '1rem',
              borderTop: '1px solid var(--border)',
            }}
          >
            <p className="text-text-secondary text-sm">
              💡 Tip: Check the browser console (F12) for more details.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
