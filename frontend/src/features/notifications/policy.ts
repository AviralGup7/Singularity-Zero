/** Client-side twin of src.notifications.policy. */

export function shouldFetchNotifications(
  bearerToken: string | null | undefined,
): bearerToken is string {
  return Boolean(bearerToken && bearerToken.trim());
}

export function shouldOpenNotificationStream(
  bearerToken: string | null | undefined,
): bearerToken is string {
  return shouldFetchNotifications(bearerToken);
}
