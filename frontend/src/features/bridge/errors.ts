export class BridgeError extends Error {
  code: string;
  status: number;
  details?: Record<string, unknown>;

  constructor(code: string, message: string, status: number, details?: Record<string, unknown>) {
    super(message);
    this.name = 'BridgeError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

const STATUS_BY_CODE: Record<string, number> = {
  bad_request: 400,
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  rate_limited: 429,
  unsupported: 422,
  payload_too_large: 413,
  protocol: 426,
  unavailable: 503,
  internal: 500,
  skipped: 204,
};

export function statusForCode(code: string): number {
  return STATUS_BY_CODE[code] ?? 500;
}

export function isRetryable(code: string): boolean {
  return code === 'rate_limited' || code === 'unavailable' || code === 'internal' || code === 'timeout' || code === 'bad_gateway';
}
