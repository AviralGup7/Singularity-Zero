export type ConsoleSessionKind = 'demo' | 'guest' | 'api_key' | 'jwt';

export function sessionHasBearerToken(kind: ConsoleSessionKind, token?: string | null): boolean {
  if (kind === 'demo' || kind === 'guest') {
    return false;
  }
  return Boolean(token && token.trim());
}
