import { test, expect } from '@playwright/test';

test.describe('Visual Regression - Replay', () => {
  test('replay page screenshot', async ({ page }) => {
    await page.goto('/replay');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    await expect(page).toHaveScreenshot('replay.png', {
      fullPage: true,
      maxDiffPixels: 100,
    });
  });
});
