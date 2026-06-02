export const APP_VERSION = '2.0.0';

// TODO: ENABLE_NOTIFICATION_DIGEST was removed — verify notificationDigest.ts has no feature-flag gating before re-adding.
export const FEATURE_FLAGS = {
  NOTIFICATION_DIGEST_MAX_ITEMS: parseInt(import.meta.env.VITE_NOTIFICATION_DIGEST_MAX_ITEMS || '50', 10),
  NOTIFICATION_DIGEST_THROTTLE_MS: parseInt(import.meta.env.VITE_NOTIFICATION_DIGEST_THROTTLE_MS || '30000', 10),
} as const;
