import { test, expect } from '@playwright/test';

test.describe('Dashboard Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      sessionStorage.setItem('cyber-pipeline-auth', JSON.stringify({
        id: 'e2e-user',
        name: 'E2E Analyst',
        role: 'analyst',
      }));
    });

    // Mock the backend API to prevent the dashboard from crashing when the server is offline
    await page.route('**/api/health/**', async (route) => {
      await route.fulfill({
        status: 200,
        json: { status: 'ok', timestamp: new Date().toISOString() }
      });
    });

    await page.route('**/api/dashboard', async (route) => {
      await route.fulfill({
        status: 200,
        json: {
          total_targets: 10,
          total_findings: 5,
          active_jobs: 2,
          pipeline_health_score: 95,
          pipeline_health_label: "Healthy",
          avg_progress: 100,
          stage_counts: {},
          severity_counts: { critical: 1, high: 2, medium: 2 },
          completed_jobs: 100,
          failed_jobs: 0,
          completed_targets: 10,
          findings_summary: { total_findings: 5, severity_totals: { critical: 1, high: 2, medium: 2 } }
        }
      });
    });

    await page.route('**/api/jobs', async (route) => {
      await route.fulfill({
        status: 200,
        json: {
          jobs: [],
          total: 0
        }
      });
    });

    await page.route('**/api/**', async (route) => {
      await route.fulfill({ status: 200, json: {} });
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');
  });

  test('dashboard loads and displays content', async ({ page }) => {
    await expect(page).toHaveTitle(/dashboard|pipeline|security/i);
  });

  test('health indicator is visible', async ({ page }) => {
    // Dump HTML to console to debug
    const html = await page.evaluate(() => document.documentElement.outerHTML);
    console.log("HTML DUMP:", html.substring(0, 1500));
    
    const healthIndicator = page.locator('text=/System Health/i');
    await expect(healthIndicator).toBeVisible({ timeout: 10000 });
  });

  test('scan launch button is accessible', async ({ page }) => {
    const newScanBtn = page.locator('a:has-text("New Scan")').first();
    await expect(newScanBtn).toBeVisible();
    await expect(newScanBtn).toHaveAttribute('href', '/targets');
  });

  test('navigation links work from dashboard', async ({ page }) => {
    const navLinks = [
      { text: /targets|target/i, expectedUrl: /\/targets/ },
      { text: /jobs|job/i, expectedUrl: /\/jobs/ },
      { text: /settings|config/i, expectedUrl: /\/settings/ },
    ];

    for (const link of navLinks) {
      const navLink = page.locator(`a:has-text("${link.text}")`).first();
      if (await navLink.isVisible()) {
        await navLink.click();
        await expect(page).toHaveURL(link.expectedUrl);
        // Click the dashboard logo to go back instead of page.goto('/')
        await page.click('h1:has-text("Cyber Pipeline"), a[href="/"]');
        await page.waitForURL('/');
      }
    }
  });

  test('dashboard handles backend offline gracefully', async ({ page }) => {
    // Override the mock to simulate offline for this specific test
    await page.route('**/api/**', (route) => route.abort('failed'));
    await page.goto('/');
    const heading = page.locator('h2:has-text("Dashboard")').first();
    await expect(heading).toBeVisible();
  });
});
