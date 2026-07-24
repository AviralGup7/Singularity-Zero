import { useEffect } from 'react';
import { motion } from 'framer-motion';
import { X, ExternalLink } from 'lucide-react';
import { safeHref } from './helpers';

interface TracePanelProps {
  tracePanel: { mode: string; trace_id?: string; job_id?: string; trace_url: string };
  onClose: () => void;
}

export function TracePanel({ tracePanel, onClose }: TracePanelProps) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
        className="absolute inset-0 bg-panel backdrop-blur-sm"
        aria-hidden="true"
      />
      <motion.div
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', stiffness: 260, damping: 30 }}
        className="relative h-full w-full max-w-3xl bg-surface border-l border-line shadow-2xl flex flex-col"
        role="dialog"
        aria-modal="true"
        aria-label="Jaeger trace"
      >
        <div className="trace-side-panel-header p-4 border-b border-line flex justify-between items-center bg-surface-2">
          <div>
            <h3 className="font-bold text-lg text-text-primary">Jaeger Trace</h3>
            <span className="text-xs text-text-secondary font-mono">
              {tracePanel.mode === 'trace' ? tracePanel.trace_id : `Search for ${tracePanel.job_id}`}
            </span>
          </div>
          <button className="btn btn-ghost btn-sm p-1.5 hover:bg-surface-hover rounded focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none" onClick={onClose} aria-label="Close trace panel">
            <X size={18} aria-hidden="true" />
          </button>
        </div>
        <iframe
          title="Jaeger trace"
          src={safeHref(tracePanel.trace_url)}
          className="flex-1 w-full border-none"
          sandbox="allow-scripts allow-same-origin allow-popups"
        />
        <div className="p-4 border-t border-line bg-surface-2 flex justify-end">
          <a
            className="btn btn-secondary text-xs flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none"
            href={safeHref(tracePanel.trace_url)}
            target="_blank"
            rel="noopener noreferrer"
          >
            <span>Open in Jaeger</span>
            <ExternalLink size={12} />
          </a>
        </div>
      </motion.div>
    </div>
  );
}
