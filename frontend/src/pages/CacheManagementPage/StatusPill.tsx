export function StatusPill({ connected }: { connected: boolean }) {
  return (
    <span className={`inline-flex items-center gap-2 text-xs font-mono ${connected ? 'text-ok' : 'text-muted'}`}>
      <span className={`h-2 w-2 rounded-full ${connected ? 'bg-ok' : 'bg-muted'}`} />
      {connected ? 'Connected' : 'Not connected'}
    </span>
  );
}
