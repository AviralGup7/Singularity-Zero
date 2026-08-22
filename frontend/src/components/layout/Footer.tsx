import { RefreshCw, Wifi, WifiOff } from 'lucide-react';

interface FooterProps {
  appVersion: string;
  isOnline: boolean;
  onRefresh: () => void;
  liveConnectionState?: string;
}

function connectionLabel(state: string): string {
  switch (state) {
    case 'connected': return 'SSE Live';
    case 'connecting': return 'Connecting...';
    case 'reconnecting': return 'Reconnecting...';
    default: return 'Polling';
  }
}

function connectionColor(state: string): string {
  switch (state) {
    case 'connected': return 'bg-ok shadow-glow-ok-sm';
    case 'connecting': return 'bg-warn shadow-glow-warn-md';
    case 'reconnecting': return 'bg-warn shadow-glow-warn-md';
    default: return 'bg-text-tertiary';
  }
}

export function Footer({ appVersion, isOnline, onRefresh, liveConnectionState }: FooterProps) {
  return (
    <footer
      className="flex flex-wrap items-center justify-between gap-2 px-6 py-3 text-xs text-text-tertiary border-t border-line bg-surface/40 backdrop-blur-sm"
      role="contentinfo"
    >
      <div className="flex items-center gap-4">
        <span className="font-mono text-[11px] font-medium text-text-tertiary/60" aria-label={`Version ${appVersion}`}>
          v{appVersion}
        </span>
        <span className="w-px h-3 bg-line" aria-hidden="true" />
        <span className="flex items-center gap-1.5" role="status" aria-live="polite">
          {isOnline
            ? <Wifi size={11} className="text-ok" aria-hidden="true" />
            : <WifiOff size={11} className="text-bad" aria-hidden="true" />
          }
          <span className={isOnline ? 'text-text-tertiary/60' : 'text-bad'}>
            {isOnline ? 'Connected' : 'Offline'}
          </span>
        </span>
        {liveConnectionState && (
          <>
            <span className="w-px h-3 bg-line" aria-hidden="true" />
            <span className="flex items-center gap-1.5" role="status" aria-live="polite" aria-label={`Connection: ${connectionLabel(liveConnectionState)}`}>
              <span className={`w-1.5 h-1.5 rounded-full inline-block ${connectionColor(liveConnectionState)}`} aria-hidden="true" />
              <span className="text-text-tertiary/60">{connectionLabel(liveConnectionState)}</span>
            </span>
          </>
        )}
      </div>
      <div className="flex items-center gap-3">
        <button
          type="button"
          className="flex items-center gap-1.5 text-text-tertiary/60 hover:text-accent transition-colors duration-200 group"
          onClick={onRefresh}
          title="Force Full System Resync (Ctrl+Shift+R)"
          aria-label="Force full system resync"
        >
          <RefreshCw size={11} className="group-hover:rotate-180 transition-transform duration-500" aria-hidden="true" />
          <span>Resync</span>
        </button>
        <span className="w-px h-3 bg-line" aria-hidden="true" />
        <span className="text-text-tertiary/40" aria-label={`Copyright ${new Date().getFullYear()}`}>
          &copy; {new Date().getFullYear()}
        </span>
      </div>
    </footer>
  );
}
