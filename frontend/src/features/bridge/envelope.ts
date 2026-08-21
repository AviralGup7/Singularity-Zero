import { PROTOCOL_VERSION } from './commands';
import type { ConsoleCommandName, RequestEnvelope, ResponseEnvelope } from './types';

export function newRequestId(): string {
  const entropy =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID().replace(/-/g, '').slice(0, 20)
      : Math.random().toString(16).slice(2, 22).padEnd(20, '0');
  return `req-${entropy}`;
}

export function buildRequest(
  command: ConsoleCommandName,
  payload: Record<string, unknown> = {},
  extra: Partial<RequestEnvelope> = {},
): RequestEnvelope {
  return {
    command,
    payload,
    request_id: extra.request_id || newRequestId(),
    protocol: extra.protocol || PROTOCOL_VERSION,
    idempotency_key: extra.idempotency_key,
    subject: extra.subject,
    bearer_token: extra.bearer_token,
    connection_id: extra.connection_id,
    path_params: extra.path_params,
    query: extra.query,
  };
}

export function isSuccess<T>(response: ResponseEnvelope<T>): boolean {
  return response.ok && !response.error;
}
