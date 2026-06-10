import { apiClient } from './core';

export interface WebhookTestResult {
  status: string;
  status_code?: number;
  latency_ms?: number;
  error?: string;
}

export async function testWebhook(
  url: string,
  secret: string,
  signal?: AbortSignal,
): Promise<WebhookTestResult> {
  const { data } = await apiClient.post<WebhookTestResult>(
    '/api/webhooks/test',
    { url, secret },
    { signal },
  );
  return data;
}

export async function testSlackWebhook(
  url: string,
  channel: string,
  signal?: AbortSignal,
): Promise<WebhookTestResult> {
  const { data } = await apiClient.post<WebhookTestResult>(
    '/api/webhooks/test-slack',
    { url, channel },
    { signal },
  );
  return data;
}
