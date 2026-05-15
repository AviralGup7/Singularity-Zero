import { test, expect } from '@playwright/test';

test.describe('Risk Score Page', () => {
  test('renders the risk heatmap for target history', async ({ page }) => {
    await page.addInitScript(() => {
      sessionStorage.setItem('cyber-pipeline-auth', JSON.stringify({
        id: 'e2e-user',
        name: 'E2E Analyst',
        role: 'analyst',
      }));
    });

    await page.route('**/api/health/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }),
      });
    });

    await page.route('**/api/targets', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          targets: [
            { name: 'api.example.com', finding_count: 3, severity_counts: { high: 2 } },
            { name: 'portal.example.com', finding_count: 2, severity_counts: { medium: 2 } },
          ],
          total: 2,
        }),
      });
    });

    await page.route(/\/api\/jobs(?:\?|$)/, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ jobs: [], total: 0 }),
      });
    });

    await page.route('**/api/risk/factors', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          weights: { cvss: 0.36, confidence: 0.22, exploitability: 0.28, mesh_consensus: 0.14 },
          factors: [
            { key: 'cvss', label: 'CVSS', description: 'Score' },
            { key: 'confidence', label: 'Confidence', description: 'Confidence' },
            { key: 'exploitability', label: 'Exploitability', description: 'Exploitability' },
            { key: 'mesh_consensus', label: 'Mesh Consensus', description: 'Consensus' },
          ],
        }),
      });
    });

    await page.route('**/api/risk/history**', async (route) => {
      const timestamp = new Date().toISOString();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            target_id: 'api.example.com',
            target: 'api.example.com',
            csi_value: 8.1,
            timestamp,
            severity_breakdown: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
            factors: { cvss: 8.5, confidence: 7.2, exploitability: 8, mesh_consensus: 6.8 },
            top_findings: [{ id: 'finding-1', title: 'Auth bypass', severity: 'critical', url: 'https://api.example.com/admin' }],
          },
          {
            target_id: 'portal.example.com',
            target: 'portal.example.com',
            csi_value: 4.6,
            timestamp,
            severity_breakdown: { critical: 0, high: 0, medium: 2, low: 1, info: 0 },
            factors: { cvss: 5, confidence: 6.2, exploitability: 4, mesh_consensus: 4.8 },
            top_findings: [{ id: 'finding-2', title: 'Verbose error', severity: 'medium', url: 'https://portal.example.com/error' }],
          },
        ]),
      });
    });

    await page.goto('/risk-score');
    await expect(page).toHaveURL(/\/risk-score/);
    await expect(page.getByTestId('risk-heatmap')).toBeVisible();
    await expect(page.locator('.risk-heat-cell').filter({ hasText: '8' }).first()).toBeVisible();
  });
});
