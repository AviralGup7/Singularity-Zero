import { test, expect } from '../utils/fixtures';

test.describe('Console Errors Audit', () => {
  test.beforeEach(async ({ mockApiResponses }) => {
    await mockApiResponses();
  });

  test('no console errors on dashboard page', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        // Ignore expected network errors if any remain, but mock should handle it
        if (!text.includes('Failed to load resource')) {
           errors.push(text);
        }
      }
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    expect(errors).toHaveLength(0);
  });

  test('no console errors on jobs page', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        if (!text.includes('Failed to load resource')) {
           errors.push(text);
        }
      }
    });

    await page.goto('/jobs');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    expect(errors).toHaveLength(0);
  });

  test('no console errors on targets page', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        if (!text.includes('Failed to load resource')) {
           errors.push(text);
        }
      }
    });

    await page.goto('/targets');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    expect(errors).toHaveLength(0);
  });

  test('no console errors on settings page', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        if (!text.includes('Failed to load resource')) {
           errors.push(text);
        }
      }
    });

    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    expect(errors).toHaveLength(0);
  });

  test('no console errors on replay page', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        if (!text.includes('Failed to load resource')) {
           errors.push(text);
        }
      }
    });

    await page.goto('/replay');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    expect(errors).toHaveLength(0);
  });

  test('no unhandled promise rejections', async ({ page }) => {
    const rejections: string[] = [];
    page.on('pageerror', (error) => {
      if (error.message.includes('Unhandled') || error.message.includes('Promise')) {
        rejections.push(error.message);
      }
    });

    const pages = ['/', '/jobs', '/targets', '/settings', '/replay'];
    for (const p of pages) {
      await page.goto(p);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1000);
    }

    expect(rejections).toHaveLength(0);
  });

  test('no failed network requests during page traversal', async ({ page }) => {
    const failedRequests: string[] = [];
    page.on('requestfailed', (request) => {
      const url = request.url();
      // Ignore favicon and other non-critical assets if they fail
      if (!url.includes('favicon.ico')) {
        failedRequests.push(url);
      }
    });

    const pages = ['/', '/jobs', '/targets', '/settings', '/replay'];
    for (const p of pages) {
      await page.goto(p);
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1000);
    }

    expect(failedRequests).toHaveLength(0);
  });
});
