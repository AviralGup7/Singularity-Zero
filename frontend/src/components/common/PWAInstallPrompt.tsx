import { usePWA } from '@/hooks/usePWA';

export function PWAInstallPrompt() {
  const { isInstallable, install } = usePWA();

  if (!isInstallable) return null;

  return (
    <div className="pwa-install-prompt">
      <span>Install app for offline access</span>
      <button className="btn btn-sm btn-primary" onClick={install}>
        Install
      </button>
    </div>
  );
}
