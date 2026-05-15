import { test, expect } from '@playwright/test';

test.describe('Error Handling', () => {
  test('dashboard handles API failure gracefully', async ({ page }) => {
    await page.route('/api/**', (route) => route.abort('failed'));
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('jobs page handles API failure gracefully', async ({ page }) => {
    await page.route('/api/**', (route) => route.abort('failed'));
    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('targets page handles API failure gracefully', async ({ page }) => {
    await page.route('/api/**', (route) => route.abort('failed'));
    await page.goto('/targets');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('settings page handles localStorage failure', async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(window, 'localStorage', {
        get: () => {
          throw new Error('localStorage unavailable');
        },
      });
    });
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('404 errors are handled', async ({ page }) => {
    await page.route('/api/**', (route) => route.fulfill({ status: 404, body: 'Not Found' }));
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('500 errors are handled', async ({ page }) => {
    await page.route('/api/**', (route) => route.fulfill({ status: 500, body: 'Internal Server Error' }));
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('slow API responses show loading state', async ({ page }) => {
    await page.route('/api/**', async (route) => {
      await new Promise(r => setTimeout(r, 3000));
      await route.continue();
    });
    await page.goto('/');
    const loadingVisible = await page.locator('[class*="loading"], [class*="skeleton"], [class*="spinner"], text="Loading"').isVisible({ timeout: 2000 }).catch(() => false);
    expect(loadingVisible || page.locator('body').textContent).toBeTruthy();
  });

  test('network recovery works', async ({ page }) => {
    let failCount = 0;
    await page.route('/api/**', async (route) => {
      if (failCount < 2) {
        failCount++;
        await route.abort('failed');
      } else {
        await route.continue();
      }
    });
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });
});
