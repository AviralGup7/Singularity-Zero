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
    <div className="fix-command-panel">
      <h4>Fix Commands</h4>
      <div className="fix-command-list">
        {suggestions.map((item) => (
          <div className="fix-command-item" key={`${item.id}-${item.command}`}>
            <div className="fix-command-head">
              <strong>{item.title}</strong>
            </div>
            <code>{item.command}</code>
            {item.rationale && <p>{item.rationale}</p>}
            {item.safety_note && <small>{item.safety_note}</small>}
          </div>
        ))}
      </div>
    </div>
  );
}
