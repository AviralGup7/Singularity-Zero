import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';

export function RouteFocusManager() {
  const location = useLocation();
  const previousPathRef = useRef(location.pathname);

  useEffect(() => {
    if (previousPathRef.current !== location.pathname) {
      const heading = document.querySelector<HTMLElement>('main h1, main h2, [data-page-heading]');
      if (heading) {
        heading.setAttribute('tabindex', '-1');
        heading.focus({ preventScroll: false });
      } else {
        const main = document.querySelector<HTMLElement>('main');
        if (main) {
          main.setAttribute('tabindex', '-1');
          main.focus({ preventScroll: false });
        }
      }
      previousPathRef.current = location.pathname;
    }
  }, [location.pathname]);

  return null;
}
