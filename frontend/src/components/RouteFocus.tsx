import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';

interface RouteFocusProps {
  children: React.ReactNode;
}

export function RouteFocus({ children }: RouteFocusProps) {
  const mainRef = useRef<HTMLElement>(null);
  const location = useLocation();

  // FIX: Add location.pathname to deps so focus re-manages on route changes
  useEffect(() => {
   
    const heading = mainRef.current?.querySelector('h1, h2, [data-focus-heading]');
    if (heading && heading instanceof HTMLElement) {
      if (!heading.hasAttribute('tabindex')) {
        heading.setAttribute('tabindex', '-1');
      }
      heading.focus({ preventScroll: false });
    } else {
      mainRef.current?.focus({ preventScroll: false });
    }
   
  }, [location.pathname]);

  return (
    <main ref={mainRef} tabIndex={-1} className="main-focus">
      {children}
    </main>
  );
}
