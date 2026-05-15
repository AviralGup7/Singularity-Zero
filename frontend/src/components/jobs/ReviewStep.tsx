interface ReviewStepProps {
  baseUrl: string;
  scopeText: string;
  selectedMode: string;
  selectedModules: Set<string>;
  executionOptions: Record<string, boolean>;
  depWarnings: { message: string }[];
}

export function ReviewStep({
  baseUrl,
  scopeText,
  selectedMode,
  selectedModules,
  executionOptions,
  depWarnings,
}: ReviewStepProps) {
  return (
    <div className="wizard-step-content">
      <h3 className="wizard-step-title">Review & Launch</h3>
      <div className="review-summary card">
        <div className="review-row">
          <span className="review-label">Base URL:</span>
          <span className="review-value">{baseUrl || '—'}</span>
        </div>
        <div className="review-row">
          <span className="review-label">Scope:</span>
          <span className="review-value">{scopeText || '—'}</span>
        </div>
        <div className="review-row">
          <span className="review-label">Mode:</span>
          <span className="review-value">{selectedMode}</span>
        </div>
        <div className="review-row">
          <span className="review-label">Modules ({selectedModules.size}):</span>
          <span className="review-value">{Array.from(selectedModules).join(', ')}</span>
        </div>
        <div className="review-row">
          <span className="review-label">Execution Options:</span>
          <span className="review-value">
            {Object.entries(executionOptions).filter(([, v]) => v).map(([k]) => k.replace(/_/g, ' ')).join(', ') || 'None'}
          </span>
        </div>
        {depWarnings.length > 0 && (
          <div className="review-row review-row-warning">
            <span className="review-label">Warnings:</span>
            <span className="review-value">
              {depWarnings.map(w => w.message).join('; ')}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
