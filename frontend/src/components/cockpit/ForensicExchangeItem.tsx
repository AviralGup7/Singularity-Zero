import type { ForensicExchange } from '@/api/cockpit';

interface ForensicExchangeItemProps {
  exchange: ForensicExchange;
  onOpen: (id: string) => void;
}

export function ForensicExchangeItem({ exchange, onOpen }: ForensicExchangeItemProps) {
  const responseStatus = exchange.response_status || exchange.response?.status;
  return (
    <button
      type="button"
      className="w-full rounded border border-line bg-surface-2 p-3 text-left transition-colors hover:bg-surface-hover focus-visible:border-accent/50 focus-visible:ring-2 focus-visible:ring-accent/30 focus-visible:outline-none"
      onClick={() => onOpen(exchange.exchange_id)}
      aria-label={`${exchange.method} ${exchange.url} — status ${responseStatus}`}
    >
      <div className="mb-1 flex items-center justify-between">
        <span className="font-mono text-[10px] text-text-secondary">{exchange.exchange_id}</span>
        <time className="text-[10px] text-text-secondary" dateTime={exchange.timestamp}>{new Date(exchange.timestamp).toLocaleTimeString()}</time>
      </div>
      <div className="flex items-center gap-2">
        <span
          className={`rounded px-1 text-[10px] font-bold tabular-nums ${
            responseStatus && responseStatus < 300 ? 'bg-ok/10 text-ok' : 'bg-bad/10 text-bad'
          }`}
        >
          {responseStatus}
        </span>
        <span className="truncate text-xs font-bold text-text-primary" title={`${exchange.method} ${exchange.url}`}>
          {exchange.method} {exchange.url}
        </span>
      </div>
    </button>
  );
}
