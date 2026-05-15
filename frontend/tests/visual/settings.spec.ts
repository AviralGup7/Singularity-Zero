import { test, expect } from '@playwright/test';

test.describe('Visual Regression - Settings', () => {
  test('settings page screenshot', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('settings.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });
});
