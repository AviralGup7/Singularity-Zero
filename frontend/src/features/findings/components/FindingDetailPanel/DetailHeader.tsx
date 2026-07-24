import { Shield, X, FileDown, Send } from 'lucide-react';
import type { Finding } from '@/types/api';
import type { ReportFormat } from '@/utils/findingExport';

interface DetailHeaderProps {
  finding: Finding;
  onExport: (format: ReportFormat) => void;
  onSubmit: () => void;
  onClose: () => void;
}

export function DetailHeader({ finding, onExport, onSubmit, onClose }: DetailHeaderProps) {
  return (
    <div className="px-8 py-6 border-b border-line flex items-center justify-between bg-surface-hover">
      <div className="flex items-center gap-4">
        <div
          className={`p-3 rounded-xl border ${
            finding.severity === 'critical'
              ? 'bg-bad/10 border-bad/20 text-bad'
              : 'bg-accent/10 border-accent/20 text-accent'
          }`}
        >
          <Shield size={24} />
        </div>
        <div>
          <h3 id="finding-detail-title" className="text-xl font-black text-text uppercase tracking-tighter">
            {finding.title}
          </h3>
          <div className="flex items-center gap-3 text-[10px] text-muted font-mono uppercase tracking-widest mt-1">
            <span>ID: {finding.id}</span>
            <span>•</span>
            <span>Target: {finding.target}</span>
          </div>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-1 mr-2" role="group" aria-label="Export this finding">
          <button
            type="button"
            className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
            onClick={() => onExport('markdown')}
            aria-label="Export as Markdown"
          >
            <FileDown size={12} aria-hidden="true" /> MD
          </button>
          <button
            type="button"
            className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
            onClick={() => onExport('html')}
            aria-label="Export as HTML"
          >
            <FileDown size={12} aria-hidden="true" /> HTML
          </button>
          <button
            type="button"
            className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
            onClick={() => onExport('json')}
            aria-label="Export as JSON"
          >
            <FileDown size={12} aria-hidden="true" /> JSON
          </button>
        </div>
        <button
          type="button"
          className="btn-primary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
          onClick={onSubmit}
          aria-label="Submit to bug-bounty platform"
          title="Submit to HackerOne / Bugcrowd / Intigriti / Synack"
        >
          <Send size={12} aria-hidden="true" /> Submit
        </button>
        <button className="text-muted hover:text-text-primary transition-colors" onClick={onClose} aria-label="Close panel">
          <X size={20} />
        </button>
      </div>
    </div>
  );
}
