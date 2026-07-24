import type { RemediationSuggestion } from '@/types/api';

interface RemediationSuggestionsProps {
  suggestions: RemediationSuggestion[];
  loading?: boolean;
}

export function RemediationSuggestions({ suggestions, loading = false }: RemediationSuggestionsProps) {
  if (loading) {
    return (
      <div className="fix-command-panel">
        <h4>Fix Commands</h4>
        <p className="fix-command-empty">Loading remediation guidance...</p>
      </div>
    );
  }

  if (suggestions.length === 0) {
    return null;
  }

  return (
    <div className="fix-command-panel" role="region" aria-label="Remediation suggestions">
      <h4>Fix Commands</h4>
      <div className="fix-command-list">
        {suggestions.map((item) => (
          <div className="fix-command-item" key={`${item.id}-${item.command}`}>
            <div className="fix-command-head">
              <strong>{item.title}</strong>
            </div>
            <code className="block text-xs p-2 bg-surface-2 rounded border border-line mt-1 break-all">{item.command}</code>
            {item.rationale && <p className="text-xs text-text-secondary mt-1">{item.rationale}</p>}
            {item.safety_note && <small className="text-xs text-warn block mt-1">{item.safety_note}</small>}
          </div>
        ))}
      </div>
    </div>
  );
}
