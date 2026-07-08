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
    case 'connected': return 'bg-[var(--ok)] shadow-[0_0_6px_var(--ok)]';
    case 'connecting': return 'bg-[var(--warn)] shadow-[0_0_6px_var(--warn)]';
    case 'reconnecting': return 'bg-[var(--warn)] shadow-[0_0_6px_var(--warn)]';
    default: return 'bg-[var(--text-tertiary)]';
  }
}

export function Footer({ appVersion, isOnline, onRefresh, liveConnectionState }: FooterProps) {
  return (
    <footer
      className="flex items-center justify-between px-6 py-3 text-xs text-[var(--text-tertiary)] border-t border-[var(--border)] bg-[var(--surface)]/40 backdrop-blur-sm"
      role="contentinfo"
    >
      <div className="flex items-center gap-4">
        <span className="font-mono text-[11px] font-medium text-[var(--text-tertiary)]/60">
          v{appVersion}
        </span>
        <span className="w-px h-3 bg-[var(--border)]" aria-hidden="true" />
        <span className="flex items-center gap-1.5">
          {isOnline
            ? <Wifi size={11} className="text-[var(--ok)]" aria-hidden="true" />
            : <WifiOff size={11} className="text-[var(--bad)]" aria-hidden="true" />
          }
          <span className={isOnline ? 'text-[var(--text-tertiary)]/60' : 'text-[var(--bad)]'}>
            {isOnline ? 'Connected' : 'Offline'}
          </span>
        </span>
        {liveConnectionState && (
          <>
            <span className="w-px h-3 bg-[var(--border)]" aria-hidden="true" />
            <span className="flex items-center gap-1.5">
              <span className={`w-1.5 h-1.5 rounded-full inline-block ${connectionColor(liveConnectionState)}`} aria-hidden="true" />
              <span className="text-[var(--text-tertiary)]/60">{connectionLabel(liveConnectionState)}</span>
            </span>
          </>
        )}
      </div>
      <div className="flex items-center gap-3">
        <button
          type="button"
          className="flex items-center gap-1.5 text-[var(--text-tertiary)]/60 hover:text-[var(--accent)] transition-colors duration-200 group"
          onClick={onRefresh}
          title="Force Full System Resync"
        >
          <RefreshCw size={11} className="group-hover:rotate-180 transition-transform duration-500" aria-hidden="true" />
          <span>Resync</span>
        </button>
        <span className="w-px h-3 bg-[var(--border)]" aria-hidden="true" />
        <span className="text-[var(--text-tertiary)]/40">
          &copy; {new Date().getFullYear()}
        </span>
      </div>
    </footer>
  );
}
