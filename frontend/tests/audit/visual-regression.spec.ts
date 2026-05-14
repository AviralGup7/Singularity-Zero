import { test, expect } from '@playwright/test';

test.describe('Visual Regression', () => {
  test('dashboard page matches baseline', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('dashboard.png', {
      maxDiffPixelRatio: 0.1,
      fullPage: true,
    });
  });

  test('jobs page matches baseline', async ({ page }) => {
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('jobs.png', {
      maxDiffPixelRatio: 0.1,
      fullPage: true,
    });
  });

  test('targets page matches baseline', async ({ page }) => {
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('targets.png', {
      maxDiffPixelRatio: 0.1,
      fullPage: true,
    });
  });

  test('settings page matches baseline', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('settings.png', {
      maxDiffPixelRatio: 0.1,
      fullPage: true,
    });
  });

  test('replay page matches baseline', async ({ page }) => {
    await page.goto('/replay');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('replay.png', {
      maxDiffPixelRatio: 0.1,
      fullPage: true,
    });
  });

  test('dark theme renders correctly', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const themeToggle = page.locator('[aria-label*="theme"], button:has-text("🌙"), button:has-text("☀️"), [data-testid="theme-toggle"]');
    if (await themeToggle.isVisible()) {
      await themeToggle.click();
      await page.waitForTimeout(500);
    }
    await expect(page).toHaveScreenshot('dashboard-dark.png', {
      maxDiffPixelRatio: 0.1,
      fullPage: true,
    });
  });

  test('scan launch form renders correctly', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const scanForm = page.locator('form').first();
    if (await scanForm.isVisible()) {
      await expect(scanForm).toHaveScreenshot('scan-form.png', {
        maxDiffPixelRatio: 0.1,
      });
    }
  });
});
