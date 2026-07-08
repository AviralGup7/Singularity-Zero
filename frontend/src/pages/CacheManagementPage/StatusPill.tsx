export function StatusPill({ connected }: { connected: boolean }) {
  return (
    <span className={`inline-flex items-center gap-2 text-xs font-mono ${connected ? 'text-[var(--ok)]' : 'text-[var(--muted)]'}`}>
      <span className={`h-2 w-2 rounded-full ${connected ? 'bg-[var(--ok)]' : 'bg-[var(--muted)]'}`} />
      {connected ? 'Connected' : 'Not connected'}
    </span>
  );
}
