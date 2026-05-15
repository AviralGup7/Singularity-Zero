import { Page } from '@playwright/test';

export interface PerformanceMetrics {
  fcp: number | undefined;
  lcp: number | undefined;
  tti: number | undefined;
  cls: number;
  domContentLoaded: number | undefined;
  loadComplete: number | undefined;
}

export async function getPerformanceMetrics(page: Page): Promise<PerformanceMetrics> {
  const performance = await page.evaluate(() => {
    const entries = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
    const paint = performance.getEntriesByType('paint');
    return {
      fcp: paint.find(e => e.name === 'first-contentful-paint')?.startTime,
      lcp: entries.loadEventEnd - entries.startTime,
      tti: entries.domInteractive - entries.startTime,
      cls: 0,
      domContentLoaded: entries.domContentLoadedEventEnd - entries.startTime,
      loadComplete: entries.loadEventEnd - entries.startTime,
    };
  });
  return performance;
}

export async function measurePageLoadTime(page: Page, url: string): Promise<number> {
  const start = Date.now();
  await page.goto(url, { waitUntil: 'networkidle' });
  return Date.now() - start;
}

export async function measureInteractionTime(page: Page, action: () => Promise<void>): Promise<number> {
  const start = Date.now();
  await action();
  await page.waitForLoadState('networkidle');
  return Date.now() - start;
}
