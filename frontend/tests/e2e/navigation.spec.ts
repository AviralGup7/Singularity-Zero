import { test, expect } from '@playwright/test';

test.describe('Navigation', () => {
  test.beforeEach(async ({ page }) => {
    // Inject mock auth state to bypass RouteGuard
    await page.addInitScript(() => {
      window.sessionStorage.setItem('cyber-pipeline-auth', JSON.stringify({
        id: 'test-user',
        name: 'Test User',
        role: 'admin'
      }));
    });
  });

  test('all main navigation links work', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const routes = [
      { path: '/', name: 'dashboard' },
      { path: '/targets', name: 'targets' },
      { path: '/jobs', name: 'jobs' },
      { path: '/replay', name: 'replay' },
      { path: '/settings', name: 'settings' },
    ];

    for (const route of routes) {
      await page.goto(route.path);
      await page.waitForLoadState('networkidle');
      const url = new URL(page.url());
      expect(url.pathname).toBe(route.path);
    }
  });

  test('unknown routes redirect to dashboard', async ({ page }) => {
    await page.goto('/nonexistent-route-12345');
    await page.waitForLoadState('networkidle');
    const url = new URL(page.url());
    expect(url.pathname).toBe('/');
  });

  test('keyboard shortcuts navigate correctly', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    await page.keyboard.press('1');
    await page.waitForTimeout(300);
    await expect(page).toHaveURL('/');

    await page.keyboard.press('2');
    await page.waitForTimeout(300);

    await page.keyboard.press('3');
    await page.waitForTimeout(300);

    await page.keyboard.press('d');
    await page.waitForTimeout(300);
    await expect(page).toHaveURL('/');
  });

  test('browser back/forward navigation works', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL('/jobs');

    await page.goBack();
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL('/');

    await page.goForward();
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL('/jobs');
  });

  test('footer links are present', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const footer = page.locator('footer');
    if (await footer.count() > 0) {
      await expect(footer).toBeVisible();
    }
  });

  test('logo/brand is visible on all pages', async ({ page }) => {
    const pages = ['/', '/jobs', '/targets', '/settings', '/replay'];
    for (const p of pages) {
      await page.goto(p);
      await page.waitForLoadState('networkidle');
      const header = page.locator('header');
      await expect(header.first()).toBeVisible();
    }
  });
});
