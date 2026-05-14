import { useState, useEffect } from 'react';
import { isPIIVisible, setPIIVisible, getPIIAuditLog, type PIIMatch } from '@/utils/piiRedactor';
import { useAuth } from '@/context/AuthContext';

interface PIIControlsProps {
  className?: string;
}

export function PIIControls({ className }: PIIControlsProps) {
  const [visible, setVisible] = useState(isPIIVisible());
  const { user } = useAuth();

  useEffect(() => {
    let mounted = true;
    Promise.resolve().then(() => {
      if (mounted) setVisible(isPIIVisible());
    });
    return () => { mounted = false; };
  }, []);

  const toggle = () => {
    const next = !visible;
    setVisible(next);
    setPIIVisible(next, user?.name || 'anonymous');
  };

  return (
    <div className={className}>
      <button
        onClick={toggle}
        className={`pii-toggle ${visible ? 'pii-visible' : 'pii-redacted'}`}
        aria-pressed={visible}
        aria-label={visible ? 'Hide PII data' : 'Show PII data'}
      >
        {visible ? '👁 PII Visible' : '🔒 PII Redacted'}
      </button>
    </div>
  );
}

export function PIIAuditLogViewer() {
  const [logs, setLogs] = useState(getPIIAuditLog());

  useEffect(() => {
    let mounted = true;
    Promise.resolve().then(() => {
      if (mounted) setLogs(getPIIAuditLog());
    });
    return () => { mounted = false; };
  }, []);

  if (logs.length === 0) return null;

  return (
    <div className="border border-[var(--line)] p-3 mt-2">
      <h4 className="font-mono text-[var(--accent)] text-xs font-bold uppercase tracking-wider mb-2">
        PII Audit Log ({logs.length})
      </h4>
      <div className="max-h-48 overflow-y-auto">
        {logs.slice(0, 50).map((entry) => (
          <div key={entry.id} className="text-xs font-mono py-1 border-b border-[var(--table-border)]">
            <span className={entry.action === 'revealed' ? 'text-[var(--warn)]' : 'text-[var(--ok)]'}>
              {entry.action}
            </span>
            {' '}
            <span className="text-[var(--text)]">{entry.category}</span>
            {' '}
            <span className="text-[var(--muted)]">
              by {entry.user} at {new Date(entry.timestamp).toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function PIIAwareText({ text, category = 'custom' }: { text: string; category?: PIIMatch['category'] }) {
  const visible = isPIIVisible();

  if (visible) {
    return <span className="pii-visible-text">{text}</span>;
  }

  const REDACTION_MAP: Record<string, string> = {
    email: '[EMAIL REDACTED]',
    phone: '[PHONE REDACTED]',
    ssn: '[SSN REDACTED]',
    creditCard: '[CARD REDACTED]',
    ipAddress: '[IP REDACTED]',
    name: '[NAME REDACTED]',
    custom: '[SENSITIVE REDACTED]',
  };

  return <span className="pii-redacted-text">{REDACTION_MAP[category] || '[REDACTED]'}</span>;
}
