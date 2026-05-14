import type { Finding } from '../../../types/api';

interface FindingsFpDialogsProps {
  fpDialogFinding: Finding | null;
  fpJustification: string;
  setFpJustification: (val: string) => void;
  onMarkFalsePositive: () => void;
  onCloseFpDialog: () => void;

  fpReviewDialog: Finding | null;
  fpReviewComment: string;
  setFpReviewComment: (val: string) => void;
  onFpReview: (finding: Finding, decision: 'approved' | 'rejected') => void;
  onCloseFpReview: () => void;
}

export function FindingsFpDialogs({
  fpDialogFinding,
  fpJustification,
  setFpJustification,
  onMarkFalsePositive,
  onCloseFpDialog,

  fpReviewDialog,
  fpReviewComment,
  setFpReviewComment,
  onFpReview,
  onCloseFpReview,
}: FindingsFpDialogsProps) {
  return (
    <>
      {fpDialogFinding && (
        <div 
          className="modal-overlay" 
          onClick={onCloseFpDialog}
          onKeyDown={e => e.key === 'Escape' && onCloseFpDialog()}
          role="presentation"
        >
          <div 
            className="modal-content fp-dialog" 
            onClick={e => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="fp-dialog-title"
          >
            <h3 id="fp-dialog-title">Mark as False Positive</h3>
            <p className="fp-dialog-finding">
              <span className={`severity-badge sev-${fpDialogFinding.severity}`}>{fpDialogFinding.severity}</span>
              {' '}{fpDialogFinding.type} on {fpDialogFinding.target}
            </p>
            <div className="form-group">
              <label htmlFor="fp-justification">Justification <span className="required">*</span></label>
              <textarea
                id="fp-justification"
                className="form-textarea"
                value={fpJustification}
                onChange={e => setFpJustification(e.target.value)}
                placeholder="Provide a detailed justification for marking this finding as a false positive..."
                rows={4}
                autoFocus
              />
            </div>
            <div className="modal-actions">
              <button className="btn btn-secondary" onClick={onCloseFpDialog}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                disabled={!fpJustification.trim()}
                onClick={onMarkFalsePositive}
              >
                Submit FP
              </button>
            </div>
          </div>
        </div>
      )}

      {fpReviewDialog && (
        <div 
          className="modal-overlay" 
          onClick={onCloseFpReview}
          onKeyDown={e => e.key === 'Escape' && onCloseFpReview()}
          role="presentation"
        >
          <div 
            className="modal-content fp-review-dialog" 
            onClick={e => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="fp-review-title"
          >
            <h3 id="fp-review-title">Review False Positive</h3>
            <p className="fp-dialog-finding">
              <span className={`severity-badge sev-${fpReviewDialog.severity}`}>{fpReviewDialog.severity}</span>
              {' '}{fpReviewDialog.type} on {fpReviewDialog.target}
            </p>
            <div className="fp-justification-preview">
              <strong>Justification:</strong>
              <p>{fpReviewDialog.fpJustification || 'No justification provided.'}</p>
            </div>
            <div className="form-group">
              <label htmlFor="fp-review-comment">Reviewer Comment (optional)</label>
              <textarea
                id="fp-review-comment"
                className="form-textarea"
                value={fpReviewComment}
                onChange={e => setFpReviewComment(e.target.value)}
                placeholder="Add a comment for this review decision..."
                rows={3}
                autoFocus
              />
            </div>
            <div className="modal-actions">
              <button className="btn btn-secondary" onClick={onCloseFpReview}>
                Cancel
              </button>
              <button
                className="btn btn-danger"
                onClick={() => onFpReview(fpReviewDialog, 'rejected')}
              >
                Reject FP
              </button>
              <button
                className="btn btn-primary"
                onClick={() => onFpReview(fpReviewDialog, 'approved')}
              >
                Approve FP
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
