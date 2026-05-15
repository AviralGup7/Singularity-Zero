import { test, expect } from '@playwright/test';

test.describe('Scan Launch', () => {
  test('scan form loads with all fields', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const urlInput = page.locator('input[placeholder*="url" i], input[placeholder*="target" i], input[type="url"]').first();
    await expect(urlInput).toBeVisible();

    const scopeInput = page.locator('textarea').first();
    await expect(scopeInput).toBeVisible();
  });

  test('url validation prevents empty submission', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const submitButton = page.locator('button[type="submit"], button:has-text("launch"), button:has-text("start"), button:has-text("run")').first();
    await expect(submitButton).toBeVisible();

    await submitButton.click();
    await page.waitForTimeout(500);

    const hasError = await page.locator(':text("required"), :text("invalid"), [role="alert"]').count() > 0;
    expect(hasError).toBeTruthy();
  });

  test('mode presets are available', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const modeButtons = page.locator('button:has-text("fast"), button:has-text("deep"), button:has-text("idor"), button:has-text("ssrf")');
    await expect(modeButtons.first()).toBeVisible();
  });

  test('module selection works', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const moduleCheckboxes = page.locator('input[type="checkbox"]');
    const count = await moduleCheckboxes.count();
    expect(count).toBeGreaterThan(0);
  });

  test('scan form accepts valid input', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const urlInput = page.locator('input[placeholder*="url" i], input[placeholder*="target" i], input[type="url"]').first();
    await urlInput.fill('https://example.com');

    const scopeInput = page.locator('textarea').first();
    await scopeInput.fill('example.com\nwww.example.com');

    const submitButton = page.locator('button[type="submit"], button:has-text("launch"), button:has-text("start"), button:has-text("run")').first();
    await expect(submitButton).toBeEnabled();
  });

  test('advanced options panel is collapsible', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const advancedToggle = page.locator('button:has-text("advanced"), button:has-text("options"), [aria-expanded]');
    if (await advancedToggle.count() > 0) {
      await advancedToggle.first().click();
      await page.waitForTimeout(300);
    }
  });
});
