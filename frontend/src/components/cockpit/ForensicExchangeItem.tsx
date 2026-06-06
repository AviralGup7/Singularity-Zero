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
      className="w-full rounded border border-line bg-black/20 p-3 text-left transition-colors hover:bg-black/40 focus:border-accent/50 focus:outline-none"
      onClick={() => onOpen(exchange.exchange_id)}
    >
      <div className="mb-1 flex items-center justify-between">
        <span className="font-mono text-[10px] text-muted">{exchange.exchange_id}</span>
        <span className="text-[10px] text-muted">{new Date(exchange.timestamp).toLocaleTimeString()}</span>
      </div>
      <div className="flex items-center gap-2">
        <span
          className={`rounded px-1 text-[10px] font-bold ${
            responseStatus && responseStatus < 300 ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400'
          }`}
        >
          {responseStatus}
        </span>
        <span className="truncate text-xs font-bold text-text">
          {exchange.method} {exchange.url}
        </span>
      </div>
    </button>
  );
}
