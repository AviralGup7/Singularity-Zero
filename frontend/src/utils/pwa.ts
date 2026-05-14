import { usePWA } from '../hooks/usePWA';

export { usePWA };

export async function unregisterStaleServiceWorkers(): Promise<void> {
  if ('serviceWorker' in navigator) {
    const registrations = await navigator.serviceWorker.getRegistrations();
    for (const registration of registrations) {
      await registration.unregister();
      console.log('SW unregistered:', registration.scope);
    }
  }

  if ('caches' in window) {
    const names = await caches.keys();
    await Promise.all(names.filter(name => name.startsWith('cyberpipe-')).map(name => caches.delete(name)));
  }
}

export function registerServiceWorker(): void {
  void unregisterStaleServiceWorkers();
}
