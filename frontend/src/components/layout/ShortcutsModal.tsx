import { FocusTrap } from '../ui/FocusTrap';

interface ShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ShortcutsModal({ isOpen, onClose }: ShortcutsModalProps) {
  if (!isOpen) return null;

  return (
    <FocusTrap active={isOpen} onDeactivate={onClose}>
      <div
        className="modal-overlay-fixed animate-fade-in"
        onClick={(e) => {
          if (e.target === e.currentTarget) onClose();
        }}
        onKeyDown={(e) => {
          if (e.key === 'Escape') onClose();
        }}
      >
        <div
          tabIndex={-1}
          className="card modal-card animate-scale-bounce"
          role="dialog"
          aria-modal="true"
          aria-labelledby="shortcuts-modal-title"
        >
          <div className="flex items-center justify-between mb-16">
            <h3 id="shortcuts-modal-title" className="text-accent font-bold text-lg">
              Keyboard Shortcuts
            </h3>
            <button
              type="button"
              className="modal-close text-xl hover:text-accent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded"
              onClick={onClose}
              aria-label="Close shortcuts modal"
            >
              &times;
            </button>
          </div>
          <div className="modal-grid space-y-2" role="list" aria-label="Keyboard shortcuts">
            {[
              { desc: 'Dashboard', key: '1' },
              { desc: 'Targets', key: '2' },
              { desc: 'Jobs', key: '3' },
              { desc: 'Findings', key: '4' },
              { desc: 'Pipeline Overview', key: '5' },
              { desc: 'Bug Bounty', key: '6' },
              { desc: 'Risk', key: '7' },
              { desc: 'Security', key: '8' },
              { desc: 'Force Refresh', key: 'R' },
              { desc: 'Show Shortcuts', key: '?' },
              { desc: 'Theme Toggle', combo: ['Ctrl', 'D'] },
              { desc: 'Settings', combo: ['Ctrl', 'S'] },
              { desc: 'Sidebar Toggle', combo: ['Ctrl', 'B'] },
              { desc: 'Command Palette', combo: ['Ctrl', 'K'] },
              { desc: 'Close Modal', key: 'Esc' },
            ].map((shortcut, idx) => (
              <div
                key={idx}
                className="shortcut-row flex items-center justify-between py-1.5 border-b border-line last:border-b-0 hover:bg-surface-hover px-2 rounded transition-colors"
                role="listitem"
              >
                <span className="text-xs text-muted/80">{shortcut.desc}</span>
                <div className="flex items-center gap-1 font-mono" aria-label={`${shortcut.desc}: ${shortcut.combo ? shortcut.combo.join(' plus ') : shortcut.key}`}>
                  {shortcut.combo ? (
                    shortcut.combo.map((k, kIdx) => (
                      <span key={kIdx} className="flex items-center">
                        <kbd className="kbd px-1.5 py-0.5 text-[10px] bg-surface-2 rounded border border-line shadow-sm">
                          {k}
                        </kbd>
                        {kIdx < shortcut.combo!.length - 1 && (
                          <span className="mx-1 text-[10px] text-muted">+</span>
                        )}
                      </span>
                    ))
                  ) : (
                    <kbd className="kbd px-1.5 py-0.5 text-[10px] bg-surface-2 rounded border border-line shadow-sm">
                      {shortcut.key}
                    </kbd>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </FocusTrap>
  );
}
