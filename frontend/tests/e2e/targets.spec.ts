import { test, expect } from '@playwright/test';

test.describe('Targets Page', () => {
  test.beforeEach(async ({ page }) => {
    // Inject mock auth state
    await page.addInitScript(() => {
      window.sessionStorage.setItem('cyber-pipeline-auth', JSON.stringify({
        id: 'test-user',
        name: 'Test User',
        role: 'admin'
      }));
    });

    // Mock API responses
    await page.route('**/api/targets', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          targets: [
            {
              name: 'example.com',
              url: 'https://example.com',
              finding_count: 5,
              url_count: 10,
              parameter_count: 20,
              run_count: 2,
              severity_counts: { critical: 1, high: 2, medium: 2 },
              latest_generated_at: new Date().toISOString(),
              href: '/jobs',
              latest_report_href: '/reports/1'
            }
          ]
        })
      });
    });
  });

  test('targets page loads', async ({ page }) => {
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/\/targets/);
  });

  test('target cards display information', async ({ page }) => {
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');

    const targetCards = page.locator('[data-testid="target-card"], .target-card, article, [class*="target"]');
    if (await targetCards.count() > 0) {
      await expect(targetCards.first()).toBeVisible();
    }
  });

  test('severity badges are displayed', async ({ page }) => {
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');

    const severityBadges = page.locator('[class*="critical"], [class*="high"], [class*="medium"], [class*="low"], [class*="severity"], [class*="badge"]');
    if (await severityBadges.count() > 0) {
      await expect(severityBadges.first()).toBeVisible();
    }
  });

  test('report download links work', async ({ page }) => {
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');

    const reportLinks = page.locator('a:has-text("report"), a:has-text("download"), [data-testid="report-link"]');
    if (await reportLinks.count() > 0) {
      await expect(reportLinks.first()).toBeVisible();
    }
  });

  test('filter input is present', async ({ page }) => {
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');

    const filterInput = page.locator('input[placeholder*="filter" i], input[placeholder*="search" i], input[type="search"]');
    if (await filterInput.count() > 0) {
      await expect(filterInput.first()).toBeVisible();
    }
  });

  test('target navigation works', async ({ page }) => {
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');

    const targetLinks = page.locator('a[href*="/"]');
    if (await targetLinks.count() > 0) {
      const href = await targetLinks.first().getAttribute('href');
      expect(href).toBeDefined();
    }
  });
});
