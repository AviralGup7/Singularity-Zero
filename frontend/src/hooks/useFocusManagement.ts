import { useEffect, useRef, useCallback } from 'react';
import { useLocation } from 'react-router-dom';

export function useFocusManagement() {
  const mainContentRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    mainContentRef.current = document.getElementById('main-content');
  }, []);

  const focusMainContent = useCallback(() => {
    const main = mainContentRef.current || document.getElementById('main-content');
    if (main) {
      if (!main.hasAttribute('tabindex')) {
        main.setAttribute('tabindex', '-1');
      }
      main.focus({ preventScroll: false });
    }
  }, []);

  const focusHeading = useCallback(() => {
    const heading = document.querySelector<HTMLElement>('[data-focus-heading]')
      || document.querySelector<HTMLElement>('h1, h2');
    if (heading) {
      if (!heading.hasAttribute('tabindex')) {
        heading.setAttribute('tabindex', '-1');
      }
      heading.focus({ preventScroll: false });
    } else {
      focusMainContent();
    }
  }, [focusMainContent]);

  return { focusMainContent, focusHeading, mainContentRef };
}

export function useFocusOnRouteChange(selector = '[data-focus-heading], h1, h2') {
  const location = useLocation();
  const hasFocusRef = useRef(false);

  useEffect(() => {
    const runFocus = () => {
      const elements = document.querySelectorAll<HTMLElement>(selector);
      for (const el of elements) {
        if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '-1');
        el.focus({ preventScroll: false });
        hasFocusRef.current = true;
        return;
      }
      const main = document.getElementById('main-content');
      if (main) {
        main.focus({ preventScroll: false });
        hasFocusRef.current = true;
      }
    };

    runFocus();
  }, [location.pathname, selector]);

  return hasFocusRef;
}

export function useFocusTrap(active: boolean, containerRef: React.RefObject<HTMLElement | null>) {
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!active) return;

    previousFocusRef.current = document.activeElement as HTMLElement;

    const container = containerRef.current;
    if (!container) return;

    const focusable = container.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    const handleTab = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;

      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };

    container.addEventListener('keydown', handleTab);

    if (focusable.length > 0) {
      setTimeout(() => focusable[0].focus(), 0);
    }

    return () => {
      container.removeEventListener('keydown', handleTab);
      if (previousFocusRef.current) {
        previousFocusRef.current.focus();
      }
    };
  }, [active, containerRef]);

  return previousFocusRef;
}
