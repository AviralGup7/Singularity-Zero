import { canCallCommand } from './authGate';
import {
  CONNECTION_HEADER,
  fillPath,
  getCommand,
  IDEMPOTENCY_HEADER,
  PROTOCOL_HEADER,
  PROTOCOL_VERSION,
  REQUEST_ID_HEADER,
  SUBJECT_HEADER,
} from './commands';
import { BridgeError } from './errors';
import { buildRequest, newRequestId } from './envelope';
import { adviceFor, parseRetryAfter, sleep } from './retry';
import type {
  ConsoleCommandName,
  ConsoleSession,
  RequestEnvelope,
  ResponseEnvelope,
} from './types';

export interface ConsoleClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  getSession?: () => ConsoleSession | null;
  getBearerToken?: () => string | null;
  getConnectionId?: () => string | null;
  getSubject?: () => string | null;
}

export class ConsoleClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly getSession?: () => ConsoleSession | null;
  private readonly getBearerToken?: () => string | null;
  private readonly getConnectionId?: () => string | null;
  private readonly getSubject?: () => string | null;

  constructor(options: ConsoleClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? '';
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.getSession = options.getSession;
    this.getBearerToken = options.getBearerToken;
    this.getConnectionId = options.getConnectionId;
    this.getSubject = options.getSubject;
  }

  async call<T = Record<string, unknown>>(
    command: ConsoleCommandName,
    payload: Record<string, unknown> = {},
    extra: Partial<RequestEnvelope> = {},
  ): Promise<ResponseEnvelope<T>> {
    const session = this.getSession?.() ?? null;
    const bearer = extra.bearer_token ?? this.getBearerToken?.() ?? null;
    const gate = canCallCommand(command, { session, bearerToken: bearer });
    if (!gate.ok) {
      return {
        ok: false,
        command,
        request_id: extra.request_id || newRequestId(),
        status: gate.reason === 'sign_in_required' ? 401 : 403,
        data: {} as T,
        error: { code: gate.reason === 'sign_in_required' ? 'unauthorized' : 'forbidden', message: gate.reason },
        protocol: PROTOCOL_VERSION,
      };
    }
    const spec = getCommand(command);
    const request = buildRequest(command, payload, {
      ...extra,
      subject: extra.subject ?? this.getSubject?.() ?? session?.subject,
      bearer_token: bearer ?? undefined,
      connection_id: extra.connection_id ?? this.getConnectionId?.() ?? undefined,
    });
    return this.send(spec.method, fillPath(spec.path, request.path_params), request);
  }

  private async send<T>(
    method: string,
    path: string,
    request: RequestEnvelope,
    attempt = 0,
  ): Promise<ResponseEnvelope<T>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      [REQUEST_ID_HEADER]: request.request_id,
      [PROTOCOL_HEADER]: request.protocol,
    };
    if (request.subject) headers[SUBJECT_HEADER] = request.subject;
    if (request.connection_id) headers[CONNECTION_HEADER] = request.connection_id;
    if (request.idempotency_key) headers[IDEMPOTENCY_HEADER] = request.idempotency_key;
    if (request.bearer_token) headers.Authorization = `Bearer ${request.bearer_token}`;

    const url = this.composeUrl(path, request.query);
    const init: RequestInit = { method, headers };
    if (method !== 'GET' && method !== 'HEAD') {
      init.body = JSON.stringify(request.payload ?? {});
    }

    let httpStatus = 0;
    let retryAfter: number | undefined;
    try {
      const res = await this.fetchImpl(url, init);
      httpStatus = res.status;
      retryAfter = parseRetryAfter(res.headers.get('Retry-After'));
      const json = (await res.json()) as ResponseEnvelope<T>;
      if (json && typeof json === 'object' && 'ok' in json) {
        if (!json.ok && json.error && adviceFor(json.error.code, attempt, retryAfter).retry) {
          const wait = adviceFor(json.error.code, attempt, retryAfter);
          await sleep(wait.afterSeconds);
          return this.send(method, path, request, attempt + 1);
        }
        return json;
      }
      return {
        ok: res.ok,
        command: request.command,
        request_id: request.request_id,
        status: res.status,
        data: json as T,
        protocol: PROTOCOL_VERSION,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'network error';
      const advice = adviceFor('unavailable', attempt, retryAfter);
      if (advice.retry) {
        await sleep(advice.afterSeconds);
        return this.send(method, path, request, attempt + 1);
      }
      throw new BridgeError('unavailable', message, httpStatus || 503);
    }
  }

  private composeUrl(path: string, query?: Record<string, unknown>): string {
    const origin = this.baseUrl.replace(/\/$/, '');
    const target = `${origin}${path}`;
    if (!query || Object.keys(query).length === 0) return target;
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === '') continue;
      params.set(key, String(value));
    }
    const qs = params.toString();
    return qs ? `${target}?${qs}` : target;
  }
}
