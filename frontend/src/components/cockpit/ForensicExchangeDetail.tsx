import type { ForensicExchange } from '@/api/cockpit';
import { Icon } from '@/components/ui/Icon';

interface ForensicExchangeDetailProps {
  exchange: ForensicExchange;
  onBack: () => void;
}

export function ForensicExchangeDetail({ exchange, onBack }: ForensicExchangeDetailProps) {
  return (
    <div className="flex h-full flex-col bg-bg" role="region" aria-label="Forensic exchange details">
      <div className="flex items-center gap-3 border-b border-line bg-surface-2 p-4">
        <button type="button" onClick={onBack} className="text-text-secondary hover:text-text-primary focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none rounded" aria-label="Back to exchange list">
          <Icon name="arrowLeft" size={18} aria-hidden="true" />
        </button>
        <div>
          <h4 className="text-sm font-bold text-text-primary">Exchange Details</h4>
          <div className="font-mono text-[10px] text-text-secondary">{exchange.exchange_id}</div>
        </div>
      </div>
      <div className="flex-1 space-y-6 overflow-y-auto p-4">
        <section aria-label="Request">
          <div className="mb-2 flex items-center justify-between">
            <h5 className="text-[10px] font-black uppercase tracking-widest text-text-secondary">Request</h5>
            <span className="text-[10px] text-text-secondary">{exchange.method}</span>
          </div>
          <div className="mb-2 break-all rounded border border-line bg-surface-2 p-3 font-mono text-[10px] text-text-primary" title={exchange.url}>
            {exchange.url}
          </div>
          <dl className="space-y-1">
            {Object.entries(exchange.request?.headers || {}).map(([key, value]) => (
              <div key={key} className="flex gap-2 text-[10px]">
                <dt className="min-w-[80px] font-bold text-text-secondary">{key}:</dt>
                <dd className="break-all text-text-primary">{value}</dd>
              </div>
            ))}
          </dl>
        </section>
        <section aria-label="Response">
          <div className="mb-2 flex items-center justify-between">
            <h5 className="text-[10px] font-black uppercase tracking-widest text-text-secondary">Response</h5>
            <span
              className={`text-[10px] font-bold tabular-nums ${
                exchange.response?.status < 400 ? 'text-ok' : 'text-bad'
              }`}
            >
              STATUS {exchange.response?.status}
            </span>
          </div>
          {exchange.response?.body_snippet && (
            <pre className="mt-3 overflow-x-auto whitespace-pre-wrap rounded bg-surface-2 p-2 text-[10px] text-text-primary">
              {exchange.response.body_snippet}
            </pre>
          )}
        </section>
      </div>
    </div>
  );
}
