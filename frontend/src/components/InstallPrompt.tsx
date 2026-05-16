import { useState } from 'react';
import { usePWA } from '@/hooks/usePWA';
import { Button } from '@/components/ui/Button';

export function InstallPrompt() {
  const { isInstallable, isInstalled, install } = usePWA();
   
  const [dismissed, setDismissed] = useState(false);

  if (isInstalled || dismissed || !isInstallable) return null;

  return (
   
    <div className="fixed bottom-4 left-4 right-4 sm:left-auto sm:max-w-sm z-[8000] bg-[var(--panel)] border border-[var(--accent)] p-4 shadow-lg">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-mono text-[var(--accent)] text-sm font-bold uppercase tracking-wider">
            Install App
          </h3>
          <p className="text-[var(--muted)] text-xs mt-1">
            Install CyberPipeline for quick access and offline support.
          </p>
        </div>
        <button
          onClick={() => setDismissed(true)}
   
          className="text-[var(--muted)] hover:text-[var(--text)] text-lg leading-none"
          aria-label="Dismiss install prompt"
        >
          ×
        </button>
      </div>
      <div className="flex gap-2 mt-3">
        <Button variant="primary" onClick={install} className="flex-1 text-xs">
          Install
        </Button>
        <Button variant="ghost" onClick={() => setDismissed(true)} className="flex-1 text-xs">
          Later
        </Button>
      </div>
    </div>
  );
}
