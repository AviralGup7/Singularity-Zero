import { apiClient } from './core';

export interface WebhookTestResult {
  status: string;
  status_code?: number;
  latency_ms?: number;
  error?: string;
}

export function isUsableWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

export async function testWebhook(
  url: string,
  secret: string,
  signal?: AbortSignal,
): Promise<WebhookTestResult> {
  if (!isUsableWebhookUrl(url)) {
    return { status: 'error', error: 'Invalid webhook URL' };
  }
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
  if (!isUsableWebhookUrl(url)) {
    return { status: 'error', error: 'Invalid Slack webhook URL' };
  }
  const { data } = await apiClient.post<WebhookTestResult>(
    '/api/webhooks/test-slack',
    { url, channel },
    { signal },
  );
  return data;
}
