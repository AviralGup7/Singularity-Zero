import { test, expect } from '@playwright/test';

test.describe('Visual Regression - Jobs', () => {
  test('jobs page screenshot', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('jobs.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });

  test('job detail page screenshot', async ({ page }) => {
    await page.goto('/jobs/test-job-id');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('job-detail.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });
});
