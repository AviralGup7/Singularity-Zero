import { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';

export function LoadingBar() {
  const location = useLocation();
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval>>(undefined);
  const hideTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const prevPathRef = useRef(location.pathname);

  useEffect(() => {
    if (prevPathRef.current !== location.pathname) {
      setLoading(true);
      setProgress(10);

      timerRef.current = setInterval(() => {
        setProgress((p) => {
          if (p >= 85) {
            clearInterval(timerRef.current);
            return 85;
          }
          return p + Math.random() * 15;
        });
      }, 300);

      const finishTimer = setTimeout(() => {
        setProgress(100);
        hideTimerRef.current = setTimeout(() => {
          setLoading(false);
          setProgress(0);
        }, 200);
      }, 800);

      prevPathRef.current = location.pathname;

      return () => {
        clearInterval(timerRef.current);
        clearTimeout(finishTimer);
        clearTimeout(hideTimerRef.current);
      };
    }
  }, [location.pathname]);

  if (!loading) return null;

  return (
    <div
      className="fixed top-0 left-0 right-0 z-[9999] h-[2px]"
      role="progressbar"
      aria-valuenow={Math.round(progress)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label="Page loading"
    >
      <div
        className="h-full transition-all duration-300 ease-out"
        style={{
          width: `${progress}%`,
          background: 'linear-gradient(90deg, var(--accent), var(--accent-2), var(--neon-cyan))',
          boxShadow: '0 0 10px var(--accent), 0 0 20px color-mix(in srgb, var(--accent) 50%, transparent)',
        }}
      />
    </div>
  );
}
