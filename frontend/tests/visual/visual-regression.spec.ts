import { test, expect } from '@playwright/test';

test.describe('Visual Regression Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
  });

  test('dashboard page visual', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveScreenshot('dashboard.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });

  test('targets page visual', async ({ page }) => {
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveScreenshot('targets.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });

  test('jobs page visual', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveScreenshot('jobs.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });

  test('job detail page visual', async ({ page }) => {
    await page.goto('/jobs/test-job-id');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveScreenshot('job-detail.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });

  test('replay page visual', async ({ page }) => {
    await page.goto('/replay');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveScreenshot('replay.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });

  test('settings page visual', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveScreenshot('settings.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });

  test('dashboard mobile visual', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveScreenshot('dashboard-mobile.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });

  test('jobs mobile visual', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveScreenshot('jobs-mobile.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });
});
