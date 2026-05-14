import { useState, useEffect, useCallback } from 'react';

// eslint-disable-next-line react-refresh/only-export-components
export function useVisibilityAPI() {
  const [isVisible, setIsVisible] = useState(!document.hidden);
  const [lastHiddenAt, setLastHiddenAt] = useState<Date | null>(null);
  const [totalHiddenTime, setTotalHiddenTime] = useState(0);

  useEffect(() => {
    let hiddenStart: Date | null = null;

    const handleVisibilityChange = () => {
      if (document.hidden) {
        setIsVisible(false);
        hiddenStart = new Date();
        setLastHiddenAt(hiddenStart);
      } else {
        setIsVisible(true);
        if (hiddenStart) {
          const hiddenDuration = Date.now() - hiddenStart.getTime();
          setTotalHiddenTime(prev => prev + hiddenDuration);
          hiddenStart = null;
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  const getHiddenDuration = useCallback(() => {
    let duration = totalHiddenTime;
    if (lastHiddenAt && !isVisible) {
      duration += Date.now() - lastHiddenAt.getTime();
    }
    return duration;
  }, [totalHiddenTime, lastHiddenAt, isVisible]);

  return {
    isVisible,
    isHidden: !isVisible,
    lastHiddenAt,
    getHiddenDuration,
  };
}

export function VisibilityIndicator() {
  const { isVisible } = useVisibilityAPI();

  if (isVisible) return null;

  return (
    <div className="visibility-paused-indicator" role="status" aria-live="polite">
      <span className="indicator-dot animate-pulse" />
      <span>Polling paused - tab is hidden</span>
    </div>
  );
}
