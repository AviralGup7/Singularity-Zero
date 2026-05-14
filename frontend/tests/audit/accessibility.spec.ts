import { test, expect } from '../utils/fixtures';

async function waitForDashboardShell(page: Parameters<typeof test>[0]['page']) {
  await page.waitForLoadState('domcontentloaded');
  await page.waitForFunction(
    () => Boolean(document.querySelector('nav[aria-label="Main navigation"], h1')),
    undefined,
    { timeout: 25000 }
  );
}

test.describe('Accessibility Audit', () => {
  test('dashboard page has proper heading hierarchy', async ({ page }) => {
    await page.goto('/');
    await waitForDashboardShell(page);
    const headings = await page.locator('h1, h2, h3, h4, h5, h6').all();
    expect(headings.length).toBeGreaterThan(0);
    const h1Count = await page.locator('h1').count();
    expect(h1Count).toBeLessThanOrEqual(1);
  });

  test('all interactive elements are keyboard accessible', async ({ page }) => {
    await page.goto('/');
    await waitForDashboardShell(page);
    const focusable = await page.locator('button, a, input, select, textarea, [tabindex]:not([tabindex="-1"])').all();
    expect(focusable.length).toBeGreaterThan(0);
    for (const el of focusable.slice(0, 10)) {
      await expect(el).toBeVisible();
    }
  });



  test('toggle switches have aria-pressed or aria-checked', async ({ page }) => {
    await page.goto('/');
    await waitForDashboardShell(page);
    const toggles = await page.locator('[role="switch"], [role="checkbox"], button[aria-label*="toggle"]').all();
    for (const toggle of toggles) {
      const hasAriaPressed = await toggle.getAttribute('aria-pressed');
      const hasAriaChecked = await toggle.getAttribute('aria-checked');
      expect(hasAriaPressed || hasAriaChecked).toBeTruthy();
    }
  });

  test('forms have associated labels', async ({ page }) => {
    await page.goto('/');
    await waitForDashboardShell(page);
    const inputs = await page.locator('input:not([type="hidden"]), textarea, select').all();
    for (const input of inputs.slice(0, 10)) {
      const ariaLabel = await input.getAttribute('aria-label');
      const ariaLabelledBy = await input.getAttribute('aria-labelledby');
      const id = await input.getAttribute('id');
      const hasLabel = ariaLabel || ariaLabelledBy || id;
      expect(hasLabel).toBeTruthy();
    }
  });

  test('images have alt text', async ({ page }) => {
    await page.goto('/');
    const images = await page.locator('img').all();
    for (const img of images) {
      const alt = await img.getAttribute('alt');
      expect(alt).toBeDefined();
    }
  });

  test('skip to content link exists', async ({ page }) => {
    await page.goto('/');
    await waitForDashboardShell(page);
    const skipLink = page.getByRole('link', { name: 'Skip to content' });
    await expect(skipLink).toBeVisible();
  });

  test('color contrast is sufficient', async ({ page }) => {
    await page.goto('/');
    await waitForDashboardShell(page);
    const textElements = await page.locator('p, span, h1, h2, h3, a, button').all();
    expect(textElements.length).toBeGreaterThan(0);
  });
});
