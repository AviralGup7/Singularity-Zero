import { lazy, type ComponentType, type LazyExoticComponent } from 'react';

const prefetchMap = new Map<string, () => Promise<unknown>>();

export function registerRoutePrefetch(path: string, loader: () => Promise<unknown>) {
  prefetchMap.set(path, loader);
}

export function prefetchRoute(path: string) {
  const loader = prefetchMap.get(path);
  if (loader) {
    loader().catch(() => {});
  }
}

export function lazyWithPrefetch(
  path: string,
  importFn: () => Promise<{ default: ComponentType }>,
): LazyExoticComponent<ComponentType> {
  registerRoutePrefetch(path, importFn);
  return lazy(importFn);
}
