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
  return sseState === 'failed';
}

export function resolveEffectiveTransport(
  transport: StreamTransport,
  sseState?: string,
): 'sse' | 'ws' {
  if (transport === 'ws' || shouldEnableWs(transport, sseState)) return 'ws';
  return 'sse';
}

const LIVE_STATUS_NOISE = new Set([
  'message',
  'progress_update',
  'progress',
  'log',
  'heartbeat',
  'ping',
  'open',
  'error',
  'completed',
]);

export function sanitizeLiveStatus(status: string | undefined): string | undefined {
  if (!status) return undefined;
  const trimmed = status.trim();
  if (!trimmed) return undefined;
  if (LIVE_STATUS_NOISE.has(trimmed.toLowerCase())) return undefined;
  return trimmed;
}
