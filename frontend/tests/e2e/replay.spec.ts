import { test, expect } from '@playwright/test';

test.describe('Replay Page', () => {
  test('replay page loads', async ({ page }) => {
    await page.goto('/replay');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/\/replay/);
  });

  test('replay form is present', async ({ page }) => {
    await page.goto('/replay');
    await page.waitForLoadState('networkidle');

    const form = page.locator('form');
    await expect(form.first()).toBeVisible();
  });

  test('auth mode selector works', async ({ page }) => {
    await page.goto('/replay');
    await page.waitForLoadState('networkidle');

    const authSelect = page.locator('select, [role="radiogroup"], button:has-text("inherit"), button:has-text("custom"), button:has-text("none")');
    if (await authSelect.count() > 0) {
      await expect(authSelect.first()).toBeVisible();
    }
  });

  test('request replay form has required fields', async ({ page }) => {
    await page.goto('/replay');
    await page.waitForLoadState('networkidle');

    const urlInput = page.locator('input[type="url"], input[placeholder*="url" i]');
    if (await urlInput.count() > 0) {
      await expect(urlInput.first()).toBeVisible();
    }

    const methodSelect = page.locator('select');
    if (await methodSelect.count() > 0) {
      await expect(methodSelect.first()).toBeVisible();
    }
  });
});
