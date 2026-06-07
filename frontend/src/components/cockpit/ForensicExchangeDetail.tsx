import type { ForensicExchange } from '@/api/cockpit';
import { Icon } from '@/components/ui/Icon';

interface ForensicExchangeDetailProps {
  exchange: ForensicExchange;
  onBack: () => void;
}

export function ForensicExchangeDetail({ exchange, onBack }: ForensicExchangeDetailProps) {
  return (
    <div className="flex h-full flex-col bg-background">
      <div className="flex items-center gap-3 border-b border-line bg-black/20 p-4">
        <button type="button" onClick={onBack} className="text-muted hover:text-text">
          <Icon name="arrowLeft" size={18} />
        </button>
        <div>
          <h4 className="text-sm font-bold text-text">Exchange Details</h4>
          <div className="font-mono text-[10px] text-muted">{exchange.exchange_id}</div>
        </div>
      </div>
      <div className="flex-1 space-y-6 overflow-y-auto p-4">
        <section>
          <div className="mb-2 flex items-center justify-between">
            <h5 className="text-[10px] font-black uppercase tracking-widest text-muted">Request</h5>
            <span className="text-[10px] text-muted">{exchange.method}</span>
          </div>
          <div className="mb-2 break-all rounded border border-line bg-black/40 p-3 font-mono text-[10px]">
            {exchange.url}
          </div>
          <div className="space-y-1">
            {Object.entries(exchange.request?.headers || {}).map(([key, value]) => (
              <div key={key} className="flex gap-2 text-[10px]">
                <span className="min-w-[80px] font-bold text-muted">{key}:</span>
                <span className="break-all text-text">{value}</span>
              </div>
            ))}
          </div>
        </section>
        <section>
          <div className="mb-2 flex items-center justify-between">
            <h5 className="text-[10px] font-black uppercase tracking-widest text-muted">Response</h5>
            <span
              className={`text-[10px] font-bold ${
                exchange.response?.status < 400 ? 'text-green-400' : 'text-red-400'
              }`}
            >
              STATUS {exchange.response?.status}
            </span>
          </div>
          {exchange.response?.body_snippet && (
            <pre className="mt-3 overflow-x-auto whitespace-pre-wrap rounded bg-black/60 p-2 text-[10px] text-text">
              {exchange.response.body_snippet}
            </pre>
          )}
        </section>
      </div>
    </div>
  );
}
