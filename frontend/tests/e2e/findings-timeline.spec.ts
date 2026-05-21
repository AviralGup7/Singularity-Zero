import { test, expect } from '@playwright/test';

test.describe('Findings Timeline Page', () => {
  test.beforeEach(async ({ page }) => {
    // Inject mock auth state
    await page.addInitScript(() => {
      window.sessionStorage.setItem('cyber-pipeline-auth', JSON.stringify({
        id: 'e2e-user',
        name: 'E2E Analyst',
        role: 'analyst',
      }));
    });

    // Mock health check API response
    await page.route('**/api/health/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }),
      });
    });

    // Mock targets API response
    await page.route('**/api/targets', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          targets: [
            { name: 'api.example.com', finding_count: 3 },
            { name: 'portal.example.com', finding_count: 2 },
          ],
          total: 2,
        }),
      });
    });

    // Mock findings timeline API response
    await page.route('**/api/findings/timeline**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'event-1',
            title: 'Authentication boundary drift',
            severity: 'critical',
            target: 'api.example.com',
            timestamp: new Date().toISOString(),
            finding_id: 'seed-finding-1',
            job_id: 'seed-job-1',
            url: 'https://api.example.com/route/0',
            module: 'seeded',
            preview: 'Seeded demonstrator event: Authentication boundary drift',
            confidence: 0.85,
          },
          {
            id: 'event-2',
            title: 'Verbose error disclosure',
            severity: 'medium',
            target: 'portal.example.com',
            timestamp: new Date().toISOString(),
            finding_id: 'seed-finding-2',
            job_id: 'seed-job-2',
            url: 'https://portal.example.com/route/1',
            module: 'seeded',
            preview: 'Seeded demonstrator event: Verbose error disclosure',
            confidence: 0.72,
          }
        ]),
      });
    });
  });

  test('timeline page loads and displays events', async ({ page }) => {
    await page.goto('/findings-timeline');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/\/findings-timeline/);

    // Verify main components are rendered
    await expect(page.locator('h2')).toHaveText('Findings Timeline');
    await expect(page.getByTestId('findings-timeline')).toBeVisible();

    // Verify events are listed in the timeline
    await expect(page.locator('.timeline-event-copy strong').first()).toContainText('Authentication boundary drift');
  });

  test('clicking an event selects it and opens details in sidebar', async ({ page }) => {
    await page.goto('/findings-timeline');
    await page.waitForLoadState('networkidle');

    // Click the first timeline event button
    await page.locator('.timeline-event-button').first().click();

    // Verify the detail sidebar displays the selected event details
    const detailPanel = page.locator('aside[aria-label="Finding detail sidebar"]');
    await expect(detailPanel).toBeVisible();
    await expect(detailPanel.locator('h3')).toHaveText('Authentication boundary drift');
    await expect(detailPanel.locator('dd').first()).toHaveText('critical');
  });
});
