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
      <div className="review-summary card" role="region" aria-label="Scan configuration review">
        <dl className="space-y-2">
          <div className="review-row">
            <dt className="review-label">Base URL:</dt>
            <dd className="review-value" title={baseUrl || undefined}>{baseUrl || '\u2014'}</dd>
          </div>
          <div className="review-row">
            <dt className="review-label">Scope:</dt>
            <dd className="review-value" title={scopeText || undefined}>{scopeText || '\u2014'}</dd>
          </div>
          <div className="review-row">
            <dt className="review-label">Mode:</dt>
            <dd className="review-value">{selectedMode}</dd>
          </div>
          <div className="review-row">
            <dt className="review-label">Modules (<span className="tabular-nums">{selectedModules.size}</span>):</dt>
            <dd className="review-value">{Array.from(selectedModules).join(', ')}</dd>
          </div>
          <div className="review-row">
            <dt className="review-label">Execution Options:</dt>
            <dd className="review-value">
              {Object.entries(executionOptions).filter(([, v]) => v).map(([k]) => k.replace(/_/g, ' ')).join(', ') || 'None'}
            </dd>
          </div>
          {depWarnings.length > 0 && (
            <div className="review-row review-row-warning">
              <dt className="review-label">Warnings:</dt>
              <dd className="review-value">
                {depWarnings.map(w => w.message).join('; ')}
              </dd>
            </div>
          )}
        </dl>
      </div>
    </div>
  );
}
