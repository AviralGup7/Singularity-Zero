import { GitMerge, XCircle, GitBranch } from 'lucide-react';

interface DetailFooterProps {
  target: string;
  url: string | undefined;
  triageStatus: string;
  duplicates: string[];
  onReplay: () => void;
  onCockpitView: () => void;
  onForensicProbe: () => void;
  onEscalate: () => void;
  onClose: () => void;
  onReopen: () => void;
  onFalsePositive: () => void;
  onMergeDuplicates: () => void;
  onDismissAsDuplicate: () => void;
  onPromoteToIndependent: () => void;
}

export function DetailFooter({
  target,
  url,
  triageStatus,
  duplicates,
  onReplay,
  onCockpitView,
  onForensicProbe,
  onEscalate,
  onClose: onCloseFinding,
  onReopen,
  onFalsePositive,
  onMergeDuplicates,
  onDismissAsDuplicate,
  onPromoteToIndependent,
}: DetailFooterProps) {
  return (
    <div className="px-8 py-6 bg-surface-hover border-t border-line flex justify-between items-center">
      <div className="flex gap-4">
        <button
          type="button"
          className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
          onClick={onReplay}
        >
          Replay with Diff
        </button>
        <button
          type="button"
          className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
          onClick={onCockpitView}
        >
          View in 3D Cockpit
        </button>
        {target && url && (
          <button
            type="button"
            className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
            onClick={onForensicProbe}
          >
            Forensic Probe
          </button>
        )}
        <button
          type="button"
          className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
          onClick={onEscalate}
          disabled={triageStatus === 'escalated'}
        >
          Escalate
        </button>
        <button
          type="button"
          className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
          onClick={onCloseFinding}
          disabled={triageStatus === 'closed'}
        >
          Close
        </button>
        <button
          type="button"
          className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
          onClick={onReopen}
          disabled={triageStatus === 'open'}
        >
          Reopen
        </button>
        <button
          type="button"
          className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
          onClick={onFalsePositive}
          disabled={triageStatus === 'false_positive'}
        >
          Flag False Positive
        </button>
        {duplicates.length > 0 && (
          <button
            type="button"
            className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
            onClick={onMergeDuplicates}
            aria-label={`Merge ${duplicates.length} duplicate(s) into this finding`}
            title="Mark all listed duplicates as merged into this primary finding"
          >
            <GitMerge size={12} aria-hidden="true" />
            Merge {duplicates.length} Dup{duplicates.length === 1 ? '' : 's'}
          </button>
        )}
        <button
          type="button"
          className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
          onClick={onDismissAsDuplicate}
          aria-label="Mark this finding as a duplicate and dismiss"
          title="Hide this finding from default triage as a duplicate"
        >
          <XCircle size={12} aria-hidden="true" />
          Dismiss as Dup
        </button>
        <button
          type="button"
          className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
          onClick={onPromoteToIndependent}
          aria-label="Promote this finding to an independent entry"
          title="Remove duplicate link and treat as standalone"
        >
          <GitBranch size={12} aria-hidden="true" />
          Promote
        </button>
      </div>
      <button
        type="button"
        className="btn-primary btn-small uppercase tracking-widest text-[9px] font-black"
        onClick={onCloseFinding}
      >
        Acknowledge
      </button>
    </div>
  );
}
