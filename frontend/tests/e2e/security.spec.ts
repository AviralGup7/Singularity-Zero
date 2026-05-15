import { test, expect } from '@playwright/test';

test.describe('Security monitor', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/health/live', route => route.fulfill({ json: { status: 'ok', timestamp: Date.now() / 1000 } }));
    await page.route('**/api/jobs', route => route.fulfill({ json: { jobs: [], total: 0 } }));
    await page.route('**/api/security/rate-limit-status', route => route.fulfill({
      json: {
        enabled: true,
        buckets: [
          { endpoint: '/api/jobs', requests_per_second: 1.2, recent_count: 6, limit_per_second: 2 },
        ],
      },
    }));
    await page.route('**/api/security/api-keys', async route => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          json: {
            id: 'key-new',
            masked_key: 'cp_new...abcd',
            api_key: 'cp_new_key_value',
            role: 'worker',
            created_at: '2026-05-10T00:00:00Z',
            last_used_at: null,
            revoked_at: null,
            active: true,
          },
        });
        return;
      }
      await route.fulfill({
        json: [
          {
            id: 'key-1',
            masked_key: 'cp_live...1234',
            role: 'admin',
            created_at: '2026-05-10T00:00:00Z',
            last_used_at: '2026-05-10T00:01:00Z',
            revoked_at: null,
            active: true,
          },
        ],
      });
    });
    await page.route('**/api/security/api-keys/*', route => route.fulfill({ json: { revoked: true, id: 'key-1' } }));
    await page.route('**/api/security/events', route => route.fulfill({
      json: [
        {
          id: 1,
          timestamp: '2026-05-10T00:00:00Z',
          event_type: 'rate_limit_hit',
          status_code: 429,
          method: 'POST',
          path: '/api/jobs',
          client_ip: '127.0.0.1',
          api_key_id: 'key-1',
          detail: 'Job creation limit exceeded',
        },
      ],
    }));
    await page.route('**/api/security/csp-reports', route => route.fulfill({
      json: [
        {
          id: 1,
          timestamp: '2026-05-10T00:00:00Z',
          client_ip: '127.0.0.1',
          user_agent: 'playwright',
          report: { 'csp-report': { 'blocked-uri': 'https://evil.example/script.js' } },
        },
      ],
    }));
  });

  test('shows security telemetry and API key controls', async ({ page }) => {
    await page.goto('/security');

    await expect(page.getByRole('heading', { name: 'Security Monitor' })).toBeVisible();
    await expect(page.getByRole('cell', { name: '/api/jobs', exact: true })).toBeVisible();
    await expect(page.getByText('rate_limit_hit')).toBeVisible();
    await expect(page.getByText('cp_live...1234')).toBeVisible();
    await expect(page.getByText('blocked-uri')).toBeVisible();

    await page.getByRole('button', { name: /Generate/i }).dispatchEvent('click');
    await expect(page.getByText('cp_new_key_value')).toBeVisible();
  });
});
