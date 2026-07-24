import { useState, useEffect, useCallback } from 'react';
import { X } from 'lucide-react';
import { getVisibilityManager } from '@/utils/visibilityManager';

export function VisibilityIndicator() {
  const [isVisible, setIsVisible] = useState(true);
  const [isDismissed, setIsDismissed] = useState(false);

  useEffect(() => {
    const manager = getVisibilityManager();

    Promise.resolve().then(() => {
      setIsVisible(manager.isDocumentVisible());
      setIsDismissed(false);
    });

    const cleanup = manager.registerCallbacks({
      onVisible: () => { setIsVisible(true); setIsDismissed(false); },
      onHidden: () => setIsVisible(false),
    });

    return cleanup;
  }, []);

  const handleDismiss = useCallback(() => setIsDismissed(true), []);

  if (isVisible || isDismissed) return null;

  return (
    <div
      className="fixed top-0 left-0 right-0 z-[9000] bg-warn/20 backdrop-blur-sm border-b border-warn py-1 text-center animate-in slide-in-from-top duration-300"
      role="status"
      aria-live="polite"
    >
      <span className="font-mono text-warn text-xs uppercase tracking-wider">
        ⏸ Polling paused — tab is hidden
      </span>
      <button
        onClick={handleDismiss}
        className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 rounded hover:bg-warn/20 text-warn transition-colors"
        aria-label="Dismiss paused indicator"
      >
        <X size={12} />
      </button>
    </div>
  );
}
