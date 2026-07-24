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
    <div className="flex flex-wrap items-center gap-2 text-xs text-muted" role="status" aria-label={`${active.length} analyst${active.length !== 1 ? 's' : ''} connected`}>
      <span className={`inline-flex items-center gap-1 font-bold ${connected ? 'text-emerald-300' : 'text-amber-300'}`}>
        <Radio size={13} className={connected ? '' : 'motion-safe:animate-pulse'} aria-hidden="true" />
        {connected ? 'Live triage' : 'Reconnecting'}
      </span>
      {active.map((analyst) => {
        const cursorArea = analyst.cursor?.area;
        const isYou = analyst.analyst_id === currentAnalystId;
        return (
          <span
            key={analyst.connection_id}
            className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-hover px-2 py-1 hover:border-accent/30 transition-colors"
            title={analyst.finding_id ? `Viewing ${analyst.finding_id}` : 'In this run'}
            aria-label={`${analyst.analyst_name}${isYou ? ' (you)' : ''}${cursorArea ? ` viewing ${cursorArea}` : ''}`}
          >
            <span className="h-2 w-2 rounded-full bg-emerald-300 motion-safe:animate-pulse" aria-hidden="true" />
            <span className="font-semibold text-text">
              {analyst.analyst_name}{isYou ? ' (you)' : ''}
            </span>
            {Boolean(cursorArea) && (
              <span className="inline-flex items-center gap-1 text-muted" aria-hidden="true">
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
