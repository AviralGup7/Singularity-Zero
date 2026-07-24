import { useState, useEffect, useRef } from 'react';
import { usePWA } from '@/hooks/usePWA';
import { Button } from '@/components/ui/Button';

interface InstallPromptProps {
  variant?: 'floating' | 'inline';
}

export function InstallPrompt({ variant = 'floating' }: InstallPromptProps) {
  const { isInstallable, isInstalled, install } = usePWA();
  const [dismissed, setDismissed] = useState(false);
  const installBtnRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!isInstalled && isInstallable && !dismissed && variant === 'floating') {
      const timer = setTimeout(() => installBtnRef.current?.focus(), 500);
      return () => clearTimeout(timer);
    }
  }, [isInstalled, isInstallable, dismissed, variant]);

  if (isInstalled || dismissed || !isInstallable) return null;

  if (variant === 'inline') {
    return (
      <div className="pwa-install-prompt" role="status" aria-label="Install app for offline access">
        <span>Install app for offline access</span>
        <button className="btn btn-sm btn-primary" onClick={install}>
          Install
        </button>
      </div>
    );
  }

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
      aria-modal="false"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-mono text-accent text-sm font-bold uppercase tracking-wider">
            Install App
          </h3>
          <p className="text-text-secondary text-sm mt-1">
            Install CyberPipeline for quick access and offline support.
          </p>
        </div>
        <button
          onClick={() => setDismissed(true)}
          className="modal-close hover:text-accent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded"
          aria-label="Dismiss install prompt"
        >
          ×
        </button>
      </div>
      <div className="flex gap-2 mt-3">
        <Button ref={installBtnRef} variant="primary" onClick={install} className="flex-1 text-xs">
          Install
        </Button>
        <Button variant="ghost" onClick={() => setDismissed(true)} className="flex-1 text-xs">
          Later
        </Button>
      </div>
    </div>
  );
}
