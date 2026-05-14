import { validateUrl } from '../../lib/utils';

interface TargetStepProps {
  baseUrl: string;
  scopeText: string;
  onBaseUrlChange: (value: string) => void;
  onScopeTextChange: (value: string) => void;
  baseUrlError: string | null;
  scopeTextError: string | null;
  onBaseUrlError: (error: string | null) => void;
  onScopeTextError: (error: string | null) => void;
}

export function TargetStep({
  baseUrl,
  scopeText,
  onBaseUrlChange,
  onScopeTextChange,
  baseUrlError,
  scopeTextError,
  onBaseUrlError,
  onScopeTextError,
}: TargetStepProps) {
  const handleBaseUrlChange = (value: string) => {
    onBaseUrlChange(value);
    if (baseUrlError) {
      const result = validateUrl(value);
      if (result.valid) onBaseUrlError(null);
      else onBaseUrlError(result.error || null);
    }
  };

  return (
    <div className="wizard-step-content">
      <h3 className="wizard-step-title">Target Selection</h3>
      <div className="mb-20">
        <label htmlFor="start-job-url" className="form-label-accent">
          Base URL
        </label>
        <textarea
          id="start-job-url"
          value={baseUrl}
          onChange={e => handleBaseUrlChange(e.target.value)}
          placeholder="https://example.com
https://example.net, https://example.org"
          rows={3}
          className={`form-input form-input-lg${baseUrlError ? ' form-input--error' : ''}`}
          required
          aria-required="true"
          aria-invalid={!!baseUrlError}
          aria-describedby={baseUrlError ? 'start-job-url-error' : undefined}
        />
        {baseUrlError && (
          <div id="start-job-url-error" className="form-error" role="alert" aria-live="polite">
            {baseUrlError}
          </div>
        )}
      </div>

      <div className="mb-20">
        <label htmlFor="start-job-scope" className="form-label-accent">
          Scope (optional, one per line)
        </label>
        <textarea
          id="start-job-scope"
          value={scopeText}
          onChange={e => { onScopeTextChange(e.target.value); if (scopeTextError) onScopeTextError(null); }}
          placeholder="example.com&#10;*.example.com&#10;api.example.com"
          className={`form-textarea form-input-lg${scopeTextError ? ' form-input--error' : ''}`}
          rows={4}
          aria-invalid={!!scopeTextError}
          aria-describedby={scopeTextError ? 'start-job-scope-error' : undefined}
        />
        {scopeTextError && (
          <div id="start-job-scope-error" className="form-error" role="alert" aria-live="polite">
            {scopeTextError}
          </div>
        )}
      </div>
    </div>
  );
}
