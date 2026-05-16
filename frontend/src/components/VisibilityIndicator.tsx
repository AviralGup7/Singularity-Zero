import { useState, useEffect } from 'react';
import { getVisibilityManager } from '@/utils/visibilityManager';

export function VisibilityIndicator() {
   
  const [isVisible, setIsVisible] = useState(true);

  useEffect(() => {
    // mounted is only read in this component, removing it entirely since cleanup handles it
    const manager = getVisibilityManager();
    
    Promise.resolve().then(() => {
      setIsVisible(manager.isDocumentVisible());
    });

    const cleanup = manager.registerCallbacks({
      onVisible: () => setIsVisible(true),
      onHidden: () => setIsVisible(false),
    });

    return cleanup;
  }, []);

  if (isVisible) return null;

  return (
    <div
   
      className="fixed top-0 left-0 right-0 z-[9000] bg-[var(--warn)]/20 border-b border-[var(--warn)] py-1 text-center"
      role="status"
      aria-live="polite"
    >
      <span className="font-mono text-[var(--warn)] text-xs uppercase tracking-wider">
        ⏸ Polling paused — tab is hidden
      </span>
    </div>
  );
}
