import { test as base, expect } from '@playwright/test';

export interface TestFixtures {
  mockApiResponses: () => Promise<void>;
}

export const test = base.extend<TestFixtures>({
  mockApiResponses: async ({ page }, applyMockApi) => {
    await applyMockApi(async () => {
      await page.route('/api/**', async (route) => {
        const url = route.request().url();
        if (url.includes('/api/health') || url.includes('/api/bloom/health')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ status: 'ok', timestamp: new Date().toISOString(), mesh_status: 'operational' }),
          });
        } else if (url.includes('/api/targets')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              targets: [
                {
                  name: 'example.com',
                  url: 'https://example.com',
                  runs: 3,
                  findings: { critical: 2, high: 5, medium: 12, low: 8, info: 15 },
                  last_run: '2024-01-15T10:30:00Z',
                  status: 'completed',
                },
              ],
            }),
          });
        } else if (url.includes('/api/jobs')) {
          const jobs = [
            {
              id: 'abc12345',
              status: 'completed',
              stage: 'completed',
              stage_label: 'Completed',
              progress_percent: 100,
              target_name: 'example.com',
              started_at: '2024-01-15T10:00:00Z',
              completed_at: '2024-01-15T10:30:00Z',
              elapsed: '30m 15s',
            },
          ];
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(url.includes('dashboard') ? jobs : { jobs }),
          });
        } else if (url.includes('/api/dashboard')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              active_jobs: 1,
              completed_jobs: 15,
              failed_jobs: 2,
              total_findings: 42,
              total_targets: 10,
              pipeline_health_score: 85,
              pipeline_health_label: 'Healthy',
              severity_counts: { critical: 2, high: 5, medium: 12, low: 8, info: 15 },
              stage_counts: { reconnaissance: 10, scanning: 5, exploitation: 2 },
              mesh: [{ id: 'node-1', status: 'online' }],
            }),
          });
        } else if (url.includes('/api/findings')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              total: 42,
              critical: 2,
              high: 5,
              medium: 12,
              low: 8,
              info: 15,
            }),
          });
        } else if (url.includes('/api/defaults')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              mode: 'fast',
              modules: ['subfinder', 'httpx', 'gau'],
              form_defaults: {},
            }),
          });
        } else if (url.includes('/api/registry')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              modules: { options: [], groups: {} },
              analysis: { options: [], groups: {}, focus_presets: {} },
              modes: { presets: {} },
            }),
          });
        } else if (url.includes('/api/dashboard-stats')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              active_jobs: 1,
              completed_jobs: 15,
              failed_jobs: 2,
              total_findings: 42,
              severity_heatmap: { critical: 2, high: 5, medium: 12, low: 8, info: 15 },
              pipeline_health_score: 85,
            }),
          });
        } else {
          await route.continue();
        }
      });
    });
  },
});

export { expect };
