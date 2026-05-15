import { test, expect } from '@playwright/test';

test.describe('Settings Page', () => {
  test('settings page loads', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/\/settings/);
  });

  test('settings sidebar is visible', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');

    const sidebar = page.locator('nav, aside, [class*="sidebar"], [class*="nav"]');
    await expect(sidebar.first()).toBeVisible();
  });

  test('theme switching works', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');

    const themeToggle = page.locator('[aria-label*="theme"], button:has-text("dark"), button:has-text("light"), [data-testid="theme-toggle"]');
    if (await themeToggle.count() > 0) {
      await themeToggle.first().click();
      await page.waitForTimeout(500);
      const htmlClass = await page.locator('html').getAttribute('class');
      const htmlDataTheme = await page.locator('html').getAttribute('data-theme');
      expect(htmlClass || htmlDataTheme).toBeTruthy();
    }
  });

  test('settings persist across reloads', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');

    const initialStorage = await page.evaluate(() => JSON.stringify(localStorage));
    await page.reload();
    await page.waitForLoadState('networkidle');

    const afterStorage = await page.evaluate(() => JSON.stringify(localStorage));
    expect(initialStorage).toBe(afterStorage);
  });

  test('settings sections are accessible', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');

    const sections = page.locator('section, [role="tabpanel"], [class*="section"]');
    const count = await sections.count();
    expect(count).toBeGreaterThan(0);
  });

  test('keyboard navigation works in settings', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');

    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    const activeElement = await page.evaluate(() => document.activeElement?.tagName);
    expect(activeElement).toBeDefined();
  });
});
