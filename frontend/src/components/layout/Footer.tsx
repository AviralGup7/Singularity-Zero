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
    case 'connected': return 'bg-ok shadow-[0_0_6px_rgba(16,185,129,0.4)]';
    case 'connecting': return 'bg-warn shadow-[0_0_6px_rgba(234,179,8,0.4)]';
    case 'reconnecting': return 'bg-warn shadow-[0_0_6px_rgba(234,179,8,0.4)]';
    default: return 'bg-muted';
  }
}

export function Footer({ appVersion, isOnline, onRefresh, liveConnectionState }: FooterProps) {
  return (
    <footer
      className="app-footer flex items-center justify-between px-6 py-4 border-t border-white/5 text-xs text-muted/60 bg-panel/30"
      role="contentinfo"
    >
      <div className="flex items-center gap-4">
        <span>v{appVersion}</span>
        {liveConnectionState && (
          <span className="flex items-center gap-1.5">
            <span className={`w-1.5 h-1.5 rounded-full inline-block ${connectionColor(liveConnectionState)}`} aria-hidden="true" />
            <span className="text-muted/50">{connectionLabel(liveConnectionState)}</span>
          </span>
        )}
      </div>
      <button
        type="button"
        className={`footer-health flex items-center gap-2 hover:text-accent transition-colors ${
          isOnline ? 'text-ok' : 'text-bad'
        }`}
        onClick={onRefresh}
        title="Force Full System Resync"
      >
        <span>System Status</span>
        <span
          className={`w-2 h-2 rounded-full inline-block ${
            isOnline ? 'bg-ok shadow-[0_0_6px_rgba(16,185,129,0.4)]' : 'bg-bad shadow-[0_0_6px_rgba(239,68,68,0.4)]'
          }`}
          aria-hidden="true"
        />
      </button>
    </footer>
  );
}
