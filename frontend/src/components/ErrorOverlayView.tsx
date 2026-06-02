import { useEffect, useLayoutEffect, useState } from 'react';
import { createRoot, type Root } from 'react-dom/client';
// captureException not used in this view; tracking handled by ErrorBoundary
// import { captureException } from '@/utils/errorTracker';

type OverlayState = {
  show: (title: string, message: string, stack?: string) => void;
  hide: () => void;
};

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

export function createErrorOverlayState(): OverlayState {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const _listeners = new Set<{ title: string; message: string; stack?: string }>();

  // eslint-disable-next-line react-hooks/rules-of-hooks
  useEffect(() => {
    const body = document.body;
    if (body) body.style.overflow = 'hidden';
    return () => {
      if (document.body) document.body.style.overflow = '';
      removeOverlayRoot();
    };
  }, []);

  const show = () => {
    ensureOverlayRoot();
  };

  // This hook is only referenced from state, hence no-op return.
  const state = {
    show,
    hide: removeOverlayRoot,
  } satisfies OverlayState;

  return state;
}

export function ErrorOverlay({ title, message, stack }: { title: string; message: string; stack?: string }) {
  const [visible, setVisible] = useState(false);

  useLayoutEffect(() => {
    const node = ensureOverlayRoot();
    if (!node) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setVisible(true);
  }, [title, message, stack]);

  useEffect(() => {
    return () => {
      setVisible(false);
      // cede control back to the state shim;
    };
  }, []);

  if (!visible) return null;

  return (
    <div
      role="alert"
      aria-live="assertive"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.85)',
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
          background: '#161b22',
          border: '1px solid #f85149',
          borderRadius: 8,
          maxWidth: 800,
          width: '100%',
          maxHeight: '90vh',
          overflow: 'auto',
          boxShadow: '0 0 40px rgba(248,81,73,0.3)',
        }}
      >
        <div
          style={{
            padding: '1rem 1.5rem',
            borderBottom: '1px solid #30363d',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <h2 style={{ color: '#f85149', margin: 0, fontSize: '1.1rem' }}>⚠️ {title}</h2>
          <button
            type="button"
            onClick={() => {
              removeOverlayRoot();
            }}
            style={{
              background: '#21262d',
              border: '1px solid #30363d',
              color: '#8b949e',
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
              background: '#0d1117',
              border: '1px solid #30363d',
              borderRadius: 6,
              padding: '1rem',
              marginBottom: '1rem',
            }}
          >
            <p style={{ color: '#f85149', margin: '0 0 0.5rem', fontWeight: 600 }}>Error Details:</p>
            <pre
              style={{
                color: '#c9d1d9',
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
          {stack ? (
            <details style={{ marginTop: '1rem' }}>
              <summary
                style={{
                  color: '#8b949e',
                  cursor: 'pointer',
                  fontSize: '0.85rem',
                  padding: '0.5rem 0',
                }}
              >
                📋 Full Stack Trace
              </summary>
              <pre
                style={{
                  background: '#0d1117',
                  border: '1px solid #30363d',
                  borderRadius: 6,
                  padding: '1rem',
                  color: '#6e7681',
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
              borderTop: '1px solid #30363d',
            }}
          >
            <p style={{ color: '#8b949e', fontSize: '0.8rem', margin: 0 }}>
              💡 Tip: Check the browser console (F12) for more details.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
