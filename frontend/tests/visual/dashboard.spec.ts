import { test, expect } from '@playwright/test';

test.describe('Visual Regression - Dashboard', () => {
  test('dashboard page screenshot', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('dashboard.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });
});
