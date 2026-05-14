import { useState, useCallback } from 'react';
import { cn } from '@/lib/utils';
import { Icon } from '@/components/Icon';
import type { EvidenceItem } from '@/types/api';

const SENSITIVE_PATTERNS = [
  { regex: /(?:Bearer\s+|token[=:\s]+|api[_-]?key[=:\s]+|access[_-]?token[=:\s]+)["']?([A-Za-z0-9\-._~+/]+=*)/gi, label: 'Token' },
  { regex: /(?:password|passwd|pwd|secret|credential)[=:\s]+["']?([^\s"']+)/gi, label: 'Credential' },
  { regex: /\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{16})\b/g, label: 'Card Number' },
  { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, label: 'Email' },
  { regex: /\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b/g, label: 'SSN/ID' },
  { regex: /(?:Authorization|Cookie|X-Api-Key|X-Auth-Token)[=:\s]+["']?([^\s"']+)/gi, label: 'Auth Header' },
];

function redactText(text: string): { redacted: string; count: number } {
  let count = 0;
  let result = text;
  for (const { regex, label } of SENSITIVE_PATTERNS) {
    const matches = result.match(regex);
    if (matches) {
      count += matches.length;
      result = result.replace(regex, `[REDACTED: ${label}]`);
    }
  }
  return { redacted: result, count };
}

function formatTimestamp(ts: string): string {
  try {
    const date = new Date(ts);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return ts;
  }
}

function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}

export interface EvidenceDisplayProps {
  evidence: EvidenceItem[];
  className?: string;
  defaultRedacted?: boolean;
}

export function EvidenceDisplay({ evidence, className, defaultRedacted = false }: EvidenceDisplayProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [redacted, setRedacted] = useState(defaultRedacted);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const toggleExpand = useCallback((id: string) => {
    setExpandedId(prev => prev === id ? null : id);
  }, []);

  const toggleRedaction = useCallback(() => {
    setRedacted(prev => !prev);
  }, []);

  const handleCopy = useCallback(async (item: EvidenceItem) => {
    const textToCopy = redacted
      ? redactText(item.raw_data).redacted
      : item.raw_data;
    try {
      await copyToClipboard(`${item.source} - ${item.timestamp}\n${item.description}\n${textToCopy}`);
      setCopiedId(item.id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // Clipboard not available
    }
  }, [redacted]);

  if (!evidence || evidence.length === 0) {
    return (
      <div className={cn('evidence-display', className)}>
        <div className="evidence-empty">
          <Icon name="shield" size={24} className="text-muted" />
          <span>No evidence available for this finding</span>
        </div>
      </div>
    );
  }

  const sortedEvidence = [...evidence].sort((a, b) =>
    new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  return (
    <div className={cn('evidence-display', className)}>
      <div className="evidence-header">
        <h3 className="evidence-title">
          <Icon name="shield" size={16} className="text-accent" />
          Evidence Timeline ({evidence.length})
        </h3>
        <button
          className={cn('evidence-redact-toggle', redacted && 'active')}
          onClick={toggleRedaction}
          aria-pressed={redacted}
        >
          <Icon name="eye-off" size={14} />
          {redacted ? 'Redaction On' : 'Redaction Off'}
        </button>
      </div>

      <div className="evidence-timeline">
        {sortedEvidence.map((item, idx) => {
          const isExpanded = expandedId === item.id;
          const { redacted: redactedText, count: redactionCount } = redactText(item.raw_data);
          const displayData = redacted ? redactedText : item.raw_data;
          const hasSensitive = redactionCount > 0;

          return (
            <div
              key={item.id || idx}
              className={cn('evidence-item', isExpanded && 'expanded', hasSensitive && 'has-sensitive')}
            >
              <div className="evidence-item-header" onClick={() => toggleExpand(item.id)}>
                <div className="evidence-timeline-dot" />
                <div className="evidence-item-meta">
                  <span className="evidence-timestamp">{formatTimestamp(item.timestamp)}</span>
                  <span className="evidence-source">{item.source}</span>
                  {hasSensitive && (
                    <span className="evidence-sensitive-badge">
                      {redactionCount} sensitive item{redactionCount > 1 ? 's' : ''}
                    </span>
                  )}
                </div>
                <div className="evidence-item-actions">
                  <button
                    className="evidence-copy-btn"
                    onClick={(e) => { e.stopPropagation(); handleCopy(item); }}
                    title="Copy evidence to clipboard"
                  >
                    {copiedId === item.id ? 'Copied!' : 'Copy'}
                  </button>
                  <span className="evidence-expand-icon">
                    {isExpanded ? '▼' : '▶'}
                  </span>
                </div>
              </div>

              <div className="evidence-item-summary">
                <span className="evidence-description">{item.description}</span>
                {item.data_type && (
                  <span className="evidence-data-type">{item.data_type}</span>
                )}
              </div>

              {isExpanded && (
                <div className="evidence-item-details">
                  <div className={cn('evidence-raw-data', redacted && 'redacted')}>
                    <div className="evidence-raw-header">
                      <span>Raw Data</span>
                      {redacted && <span className="redacted-label">[REDACTED]</span>}
                    </div>
                    <pre>{displayData}</pre>
                  </div>

                  {item.sensitive && (
                    <div className="evidence-sensitive-notice">
                      <Icon name="alert-triangle" size={14} />
                      This evidence contains sensitive data
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
