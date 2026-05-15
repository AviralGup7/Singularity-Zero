import { test, expect } from '@playwright/test';

test.describe('Visual Regression - Targets', () => {
  test('targets page screenshot', async ({ page }) => {
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('targets.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });
});
