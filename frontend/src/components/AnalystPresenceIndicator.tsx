import { useState, useEffect, useMemo } from 'react';
import { MousePointer2, Radio } from 'lucide-react';
import type { AnalystPresence } from '@/api/triage';

export function AnalystPresenceIndicator({
  analysts,
  currentAnalystId,
  connected,
}: {
  analysts: AnalystPresence[];
  currentAnalystId: string;
  connected: boolean;
}) {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 10000);
    return () => clearInterval(timer);
  }, []);

  const active = useMemo(() => {
    return analysts.filter((analyst) => now / 1000 - analyst.last_seen < 90);
  }, [analysts, now]);

  return (
    <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
      <span className={`inline-flex items-center gap-1 font-bold ${connected ? 'text-emerald-300' : 'text-amber-300'}`}>
        <Radio size={13} />
        {connected ? 'Live triage' : 'Reconnecting'}
      </span>
      {active.map((analyst) => {
        const cursorArea = analyst.cursor?.area;
        return (
          <span
            key={analyst.connection_id}
            className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-1"
            title={analyst.finding_id ? `Viewing ${analyst.finding_id}` : 'In this run'}
          >
            <span className="h-2 w-2 rounded-full bg-emerald-300" />
            <span className="font-semibold text-text">
              {analyst.analyst_name}{analyst.analyst_id === currentAnalystId ? ' (you)' : ''}
            </span>
            {Boolean(cursorArea) && (
              <span className="inline-flex items-center gap-1 text-muted">
                <MousePointer2 size={12} />
                {String(cursorArea)}
              </span>
            )}
          </span>
        );
      })}
    </div>
  );
}
