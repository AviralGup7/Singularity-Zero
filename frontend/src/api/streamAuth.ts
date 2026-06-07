/**
 * Stream auth helpers.
 *
 * SSE and WebSocket transports can't use the standard Authorization header
 * (EventSource has no header support; WebSocket subprotocols leak the token
 * into access logs on some proxies). The codebase falls back to passing the
 * bearer token as a `token` query-string parameter for these endpoints.
 *
 * Centralising the read in this module means:
 *   1. There is exactly one place that knows the storage key, so changing
 *      the auth backend only requires editing one file.
 *   2. We can later swap this to a short-lived `/api/stream-token` exchange
 *      (giving us revocation) without grepping the codebase.
 *   3. Components, hooks, and the REST interceptor all read from the same
 *      source, eliminating drift between `sessionStorage.getItem('auth_token')`
 *      and `safeSession.get('auth_token')`.
 *
 * SECURITY: The query-string transport is documented as non-ideal; the goal
 * of this module is to make that compromise *findable* and *swappable*.
 */

import { safeSession } from '@/utils/storage';

export const AUTH_TOKEN_KEY = 'auth_token';

/**
 * Returns the current auth bearer token, or `null` if the user is
 * unauthenticated / the token has expired. Reads from `safeSession` so a
 * blocked `sessionStorage` (private mode, locked-down policy) gracefully
 * falls back to the in-memory map instead of throwing.
 */
export function getStreamToken(): string | null {
  return safeSession.get(AUTH_TOKEN_KEY);
}

/**
 * Appends the auth token to a `URLSearchParams`-style query string.
 * Returns the original URL untouched when no token is available so we never
 * ship `?token=` to the wire.
 */
export function appendStreamToken(url: string): string {
  const token = getStreamToken();
  if (!token) return url;
  const separator = url.includes('?') ? '&' : '?';
  return `${url}${separator}token=${encodeURIComponent(token)}`;
}

/**
 * Builds a list of WebSocket subprotocols that the backend accepts for
 * auth. The backend's `/ws/logs/{jobId}` handler reads the token from
 * the `access_token` subprotocol. We return an empty array when no token
 * is present so the connection is allowed (the backend will reject the
 * upgrade with 401).
 */
export function getStreamSubprotocols(): string[] {
  const token = getStreamToken();
  return token ? ['access_token', token] : [];
}
