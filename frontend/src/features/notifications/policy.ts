/** Client-side twin of src.notifications.policy. */

export function shouldFetchNotifications(bearerToken: string | null | undefined): boolean {
  return Boolean(bearerToken && bearerToken.trim());
}

export function shouldOpenNotificationStream(bearerToken: string | null | undefined): boolean {
  return shouldFetchNotifications(bearerToken);
}
