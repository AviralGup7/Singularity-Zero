let isOnline = true;
if (typeof window !== 'undefined') {
  isOnline = navigator.onLine;
  window.addEventListener('online', () => { isOnline = true; });
  window.addEventListener('offline', () => { isOnline = false; });
}

export function getOnlineStatus(): boolean {
  return isOnline;
}
