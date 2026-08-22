export function isTerminalSseEvent(eventType: string | undefined, data?: Record<string, unknown>): boolean {
  if (eventType === 'completed') return true;
  if (eventType === 'error' && data && data.recoverable === false) return true;
  return false;
}

export function shouldEnqueueSseEvent(eventType: string | undefined): boolean {
  return eventType !== 'heartbeat' && eventType !== 'ping';
}
