export type StreamTransport = 'sse' | 'ws' | 'auto';

export function shouldEnableSse(transport: StreamTransport): boolean {
  return transport === 'sse' || transport === 'auto';
}

export function shouldEnableWs(
  transport: StreamTransport,
  sseState?: string,
): boolean {
  if (transport === 'ws') return true;
  if (transport !== 'auto') return false;
  return sseState === 'failed' || sseState === 'closed';
}
