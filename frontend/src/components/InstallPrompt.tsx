import { useState } from 'react';
import { usePWA } from '@/hooks/usePWA';
import { Button } from '@/components/ui/Button';

export function InstallPrompt() {
  const { isInstallable, isInstalled, install } = usePWA();
   
  const [dismissed, setDismissed] = useState(false);

  if (isInstalled || dismissed || !isInstallable) return null;

  return (
    <div
      className="fixed bottom-4 left-4 right-4 sm:left-auto sm:max-w-sm z-[8000] p-4 shadow-lg animate-fade-in-up"
      style={{
        background: 'var(--glass-bg)',
        backdropFilter: 'blur(var(--glass-blur))',
        WebkitBackdropFilter: 'blur(var(--glass-blur))',
        border: '1px solid var(--glass-border)',
        borderRadius: 'var(--radius-lg)',
      }}
      role="dialog"
      aria-label="Install application"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontSize: 'var(--text-small)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Install App
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-small)', marginTop: '4px' }}>
            Install CyberPipeline for quick access and offline support.
          </p>
        </div>
        <button
          onClick={() => setDismissed(true)}
          className="modal-close"
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
