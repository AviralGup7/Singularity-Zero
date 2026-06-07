interface FooterProps {
  appVersion: string;
  isOnline: boolean;
  onRefresh: () => void;
}

export function Footer({ appVersion, isOnline, onRefresh }: FooterProps) {
  return (
    <footer
      className="app-footer flex items-center justify-between px-6 py-4 border-t border-white/5 text-xs text-muted/60 bg-panel/30"
      role="contentinfo"
    >
      <span>v{appVersion}</span>
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
