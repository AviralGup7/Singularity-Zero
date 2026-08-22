import { useEffect, useState } from 'react';
import { getStreamToken } from '@/api/streamAuth';
import { sessionHasBearerToken } from '@/features/auth/session';
import { useAuth } from '@/hooks/useAuth';
import { useSessionTimeout } from '@/hooks/useSessionTimeout';
import { useSettingsStore } from '@/stores/settingsStore';
import { SessionLockScreen, SessionWarningModal } from '@/components/SessionLock';
import { normalizeAutoLogoutMinutes, subscribeStreamToken } from '@/hooks/sessionUnlock';

function TokenSessionLock({ timeoutMs, requirePassword }: { timeoutMs: number; requirePassword: boolean }) {
  const { verifyUnlockPassword } = useAuth();
  const { isLocked, showWarning, remainingMs, unlock, lock } = useSessionTimeout(undefined, timeoutMs);
  const secondsRemaining = Math.max(0, Math.ceil(remainingMs / 1000));

  if (isLocked) {
    return (
      <SessionLockScreen
        requirePassword={requirePassword}
        onUnlock={(password) => {
          if (requirePassword && !verifyUnlockPassword(password)) {
            return false;
          }
          unlock();
          return true;
        }}
      />
    );
  }

  if (showWarning) {
    return (
      <SessionWarningModal
        secondsRemaining={secondsRemaining}
        onDismiss={unlock}
        onLockNow={lock}
      />
    );
  }

  return null;
}

/** Token-backed idle lock only. Demo / guest never lock. */
export function shouldEnableSessionLock(
  userPresent: boolean,
  token: string | null | undefined,
  autoLogoutMinutes: number,
): boolean {
  const hasToken = sessionHasBearerToken(token ? 'jwt' : 'demo', token);
  return Boolean(userPresent && hasToken && autoLogoutMinutes > 0);
}

/**
 * Idle lock for token-backed sessions only.
 * Demo / guest never lock. Enabled when Settings → Security auto-logout minutes > 0.
 */
export function SessionGuard() {
  const { user } = useAuth();
  const minutes = normalizeAutoLogoutMinutes(useSettingsStore((state) => state.settings.security.autoLogoutMinutes));
  const [token, setToken] = useState(() => getStreamToken());
  useEffect(() => subscribeStreamToken(() => setToken(getStreamToken())), []);
  const enabled = shouldEnableSessionLock(Boolean(user), token, minutes);
  const requirePassword = Boolean((user as { unlockPassword?: string } | null)?.unlockPassword);

  if (!enabled) {
    return null;
  }

  return <TokenSessionLock timeoutMs={minutes * 60 * 1000} requirePassword={requirePassword} />;
}
