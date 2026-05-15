import { useState, useEffect } from 'react';
import type { ReactNode } from 'react';

interface PageTransitionProps {
  children: ReactNode;
  locationKey?: string;
}

export function PageTransition({ children, locationKey }: PageTransitionProps) {
  const [isVisible, setIsVisible] = useState(false);
  // FIX: Use state with matchMedia listener instead of ref (ref never updates)
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const handler = (e: MediaQueryListEvent) => setPrefersReducedMotion(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);

  useEffect(() => {
    if (prefersReducedMotion) {
      Promise.resolve().then(() => {
        setIsVisible(true);
      });
      return;
    }

    const timer = requestAnimationFrame(() => {
      setIsVisible(true);
    });

    return () => cancelAnimationFrame(timer);
  }, [locationKey, prefersReducedMotion]);

  if (prefersReducedMotion) {
    return <>{children}</>;
  }

  return (
    <div
      className={`page-transition ${isVisible ? 'page-enter-active' : 'page-enter'}`}
      key={locationKey}
    >
      {children}
    </div>
  );
}
