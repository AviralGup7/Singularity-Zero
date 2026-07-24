import { lazy   } from 'react';
import type {ComponentType, LazyExoticComponent} from 'react';

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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  importFn: () => Promise<{ default: ComponentType<any> }>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): LazyExoticComponent<ComponentType<any>> {
  registerRoutePrefetch(path, importFn);
  return lazy(importFn);
}
