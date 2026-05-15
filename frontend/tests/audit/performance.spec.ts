import { test, expect } from '@playwright/test';
import { getPerformanceMetrics, measurePageLoadTime } from '../utils/performance';

test.describe('Performance Audit', () => {
  test('dashboard loads within 2 seconds', async ({ page }) => {
    const loadTime = await measurePageLoadTime(page, '/');
    expect(loadTime).toBeLessThan(2000);
  });

  test('jobs page loads within 1.5 seconds', async ({ page }) => {
    const loadTime = await measurePageLoadTime(page, '/jobs');
    expect(loadTime).toBeLessThan(1500);
  });

  test('targets page loads within 1.5 seconds', async ({ page }) => {
    const loadTime = await measurePageLoadTime(page, '/targets');
    expect(loadTime).toBeLessThan(1500);
  });

  test('settings page loads within 1 second', async ({ page }) => {
    const loadTime = await measurePageLoadTime(page, '/settings');
    expect(loadTime).toBeLessThan(1000);
  });

  test('first contentful paint is under 1 second', async ({ page }) => {
    await page.goto('/');
    const metrics = await getPerformanceMetrics(page);
    expect(metrics.fcp).toBeDefined();
    expect(metrics.fcp).toBeLessThan(1000);
  });

  test('time to interactive is under 2 seconds', async ({ page }) => {
    await page.goto('/');
    const metrics = await getPerformanceMetrics(page);
    expect(metrics.tti).toBeDefined();
    expect(metrics.tti).toBeLessThan(2000);
  });

  test('no long tasks blocking main thread', async ({ page }) => {
    await page.goto('/');
    const longTasks = await page.evaluate(() => {
      return new Promise<number>((resolve) => {
        let count = 0;
        const observer = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (entry.duration > 50) count++;
          }
        });
        try {
          observer.observe({ type: 'longtask', buffered: true });
          setTimeout(() => { observer.disconnect(); resolve(count); }, 2000);
        } catch {
          resolve(0);
        }
      });
    });
    expect(longTasks).toBeLessThan(5);
  });

  test('bundle size is reasonable', async ({ page }) => {
    await page.goto('/');
    const resources = await page.evaluate(() => {
      return performance.getEntriesByType('resource')
        .filter((r: PerformanceResourceTiming) => r.initiatorType === 'script')
        .map((r: PerformanceResourceTiming) => ({
          name: r.name,
          size: r.transferSize,
        }));
    });
    const totalSize = resources.reduce((sum: number, r: { size: number }) => sum + r.size, 0);
    expect(totalSize).toBeLessThan(1000000);
  });
});
