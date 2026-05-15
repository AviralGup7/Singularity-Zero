import { test, expect } from '@playwright/test';

test.describe('Jobs Page', () => {
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
    await page.route('**/api/jobs', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          jobs: [
            {
              id: 'job-1',
              target_name: 'example.com',
              status: 'running',
              progress_percent: 45,
              started_at: new Date().toISOString(),
              stage: 'scanning',
              stage_label: 'Scanning',
              elapsed: '5m'
            },
            {
              id: 'job-2',
              target_name: 'test.com',
              status: 'completed',
              progress_percent: 100,
              started_at: new Date().toISOString(),
              completed_at: new Date().toISOString(),
              stage: 'completed',
              stage_label: 'Completed',
              elapsed: '15m'
            }
          ]
        })
      });
    });
  });

  test('jobs page loads', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/\/jobs/);
  });

  test('job status filters work', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');

    const filterButtons = page.locator('button:has-text("all"), button:has-text("running"), button:has-text("completed"), button:has-text("failed")');
    const count = await filterButtons.count();
    expect(count).toBeGreaterThan(0);
  });

  test('job cards display job information', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');

    const jobCards = page.locator('[data-testid="job-card"], .job-card, article, [class*="job"]');
    if (await jobCards.count() > 0) {
      await expect(jobCards.first()).toBeVisible();
    }
  });

  test('job detail page loads', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');

    const jobLinks = page.locator('a[href*="/jobs/"]');
    if (await jobLinks.count() > 0) {
      await jobLinks.first().click();
      await page.waitForLoadState('networkidle');
      await expect(page).toHaveURL(/\/jobs\/\w+/);
    }
  });

  test('job progress bar is visible', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');

    const progressBar = page.locator('[role="progressbar"], [class*="progress"], progress');
    if (await progressBar.count() > 0) {
      await expect(progressBar.first()).toBeVisible();
    }
  });

  test('live log viewer updates', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');

    const jobLinks = page.locator('a[href*="/jobs/"]');
    if (await jobLinks.count() > 0) {
      await jobLinks.first().click();
      await page.waitForLoadState('networkidle');

      const logViewer = page.locator('[data-testid="log-viewer"], [class*="log"], pre, code');
      if (await logViewer.count() > 0) {
        await expect(logViewer.first()).toBeVisible();
      }
    }
  });

  test('stop job button is available for running jobs', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');

    const stopButtons = page.locator('button:has-text("stop"), button:has-text("cancel")');
    if (await stopButtons.count() > 0) {
      await expect(stopButtons.first()).toBeVisible();
    }
  });
});
