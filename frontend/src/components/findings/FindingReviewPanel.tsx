import { useState, useCallback } from 'react';
import { Loader2, Check, X, ChevronDown, ChevronUp, ShieldAlert } from 'lucide-react';

const ACTION_TYPES = [
  { id: 'confirm_tp', label: 'Confirm TP', icon: Check, color: 'accent' },
  { id: 'dismiss_fp', label: 'Dismiss FP', icon: X, color: 'muted' },
  { id: 'downgrade_severity', label: 'Downgrade', icon: ChevronDown, color: 'warn' },
  { id: 'upgrade_severity', label: 'Escalate', icon: ChevronUp, color: 'critical' },
  { id: 'request_validation', label: 'Request Validation', icon: ShieldAlert, color: 'muted' },
] as const;

export type ReviewActionType = (typeof ACTION_TYPES)[number]['id'];

interface FindingReviewPanelProps {
  findingId: string;
  defaultReviewer?: string;
  onAction?: (action: ReviewActionType, note: string) => Promise<void> | void;
}

/**
 * Structured-review panel used by analysts to record an
 * ``override_source=analyst_triage`` feedback event. Every action
 * requires a non-empty structured note (the ``FindingReviewPanel``
 * never writes back a row to ``feedback_events`` without a note,
 * which keeps the active-learning loop's audit trail meaningful).
 */
export function FindingReviewPanel({
  findingId,
  defaultReviewer = 'analyst',
  onAction,
}: FindingReviewPanelProps) {
  const [activeAction, setActiveAction] = useState<ReviewActionType | null>(null);
  const [note, setNote] = useState('');
  const [reviewerId, setReviewerId] = useState(defaultReviewer);
  const [submitting, setSubmitting] = useState(false);
  const [lastResult, setLastResult] = useState<string | null>(null);

  const handleAction = useCallback(
    async (action: ReviewActionType) => {
      if (!note.trim()) {
        setActiveAction(action);
        return;
      }
      setSubmitting(true);
      try {
        if (onAction) {
          await onAction(action, note);
        } else {
          const res = await fetch(`/api/risk-domain/findings/${encodeURIComponent(findingId)}/review`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              action_type: action,
              reviewer_id: reviewerId,
              structured_note: note,
            }),
          });
          if (!res.ok) {
            throw new Error(`Review submit failed: ${res.status}`);
          }
        }
        setLastResult(`Recorded ${action}`);
        setNote('');
        setActiveAction(null);
      } catch (err) {
        setLastResult(`Error: ${(err as Error).message}`);
      } finally {
        setSubmitting(false);
      }
    },
    [findingId, note, onAction, reviewerId],
  );

  return (
    <div className="glass-panel border border-white/5 rounded-lg p-4 space-y-3" data-testid="finding-review-panel">
      <div className="flex items-center justify-between">
        <h3 className="text-[10px] font-black uppercase tracking-widest text-muted">Analyst Review</h3>
        <span className="text-[9px] text-muted font-mono">{findingId}</span>
      </div>
      <div className="flex items-center gap-2">
        <label htmlFor="reviewer-id" className="text-[9px] uppercase tracking-widest text-muted">
          Reviewer
        </label>
        <input
          id="reviewer-id"
          type="text"
          value={reviewerId}
          onChange={(e) => setReviewerId(e.target.value)}
          className="flex-1 bg-white/5 border border-white/10 rounded text-[11px] font-mono px-2 py-1 text-text focus:border-accent/50 outline-none"
          placeholder="reviewer-id"
        />
      </div>
      <div className="grid grid-cols-2 gap-2">
        {ACTION_TYPES.map(({ id, label, icon: Icon }) => {
          const isActive = activeAction === id;
          return (
            <button
              key={id}
              type="button"
              disabled={submitting}
              onClick={() => handleAction(id)}
              className={`flex items-center gap-2 px-2 py-1.5 rounded text-[10px] font-black uppercase tracking-widest border transition-all ${
                isActive
                  ? 'bg-accent/20 border-accent/40 text-accent'
                  : 'border-white/5 text-muted hover:border-white/10 hover:text-text'
              }`}
              aria-pressed={isActive}
              data-action={id}
            >
              <Icon size={12} aria-hidden="true" />
              {label}
            </button>
          );
        })}
      </div>
      {activeAction && (
        <div className="space-y-2">
          <label htmlFor="review-note" className="text-[9px] uppercase tracking-widest text-muted">
            Structured note (required)
          </label>
          <textarea
            id="review-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Why is this a TP / FP / downgraded / escalated? Cite evidence or run id."
            className="w-full bg-white/5 border border-white/10 rounded text-[11px] font-mono px-2 py-1.5 text-text focus:border-accent/50 outline-none resize-none h-20"
          />
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={submitting || !note.trim()}
              onClick={() => handleAction(activeAction)}
              className="btn-primary btn-small flex items-center gap-2"
            >
              {submitting ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
              Submit
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveAction(null);
                setNote('');
              }}
              className="btn-secondary btn-small"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      {lastResult && (
        <div
          className={`text-[10px] font-mono ${
            lastResult.startsWith('Error') ? 'text-critical' : 'text-accent'
          }`}
          role="status"
          aria-live="polite"
        >
          {lastResult}
        </div>
      )}
    </div>
  );
}

export default FindingReviewPanel;
