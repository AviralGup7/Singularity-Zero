import { useState, useCallback } from 'react';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { useAuth } from '@/hooks/useAuth';

interface SessionLockScreenProps {
  onUnlock: (password: string) => boolean;
}

export function SessionLockScreen({ onUnlock }: SessionLockScreenProps) {
   
  const [password, setPassword] = useState('');
   
  const [error, setError] = useState('');
  const { user, verifyUnlockPassword } = useAuth();

  const handleUnlock = useCallback(() => {
    if (verifyUnlockPassword(password)) {
      onUnlock(password);
      setError('');
      setPassword('');
    } else {
      setError('Incorrect password');
    }
   
  }, [password, onUnlock, verifyUnlockPassword]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleUnlock();
  };

  return (
   
    <div className="fixed inset-0 z-[10000] bg-[var(--bg)] flex items-center justify-center" role="dialog" aria-modal="true" aria-label="Session locked">
  // eslint-disable-next-line security/detect-object-injection
      <div className="w-full max-w-sm p-6 border border-[var(--line)] bg-[var(--panel)]">
        <div className="text-center mb-4">
          <div className="text-2xl mb-2" aria-hidden="true">🔒</div>
  // eslint-disable-next-line security/detect-object-injection
          <h2 id="session-lock-title" className="font-mono text-[var(--accent)] text-lg font-bold uppercase tracking-wider">
            Session Locked
          </h2>
  // eslint-disable-next-line security/detect-object-injection
          <p className="text-[var(--muted)] text-sm mt-1">
            {user?.name || 'User'} — Re-authenticate to continue
          </p>
        </div>

        <Input
          id="unlock-password"
          type="password"
          label="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={handleKeyDown}
          error={error}
          placeholder="Enter password"
          className="mb-3"
        />

        <Button
          variant="primary"
          onClick={handleUnlock}
          className="w-full"
          disabled={!password}
        >
          Unlock
        </Button>
      </div>
    </div>
  );
}

export function SessionWarningModal({
  secondsRemaining,
  onDismiss,
  onLockNow,
}: {
  secondsRemaining: number;
  onDismiss: () => void;
  onLockNow: () => void;
}) {
  return (
   
    <div className="fixed inset-0 z-[9999] bg-[var(--modal-overlay)] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Session expiring warning">
  // eslint-disable-next-line security/detect-object-injection
      <div className="w-full max-w-sm p-6 border border-[var(--warn)] bg-[var(--panel)]">
        <div className="text-center mb-4">
          <div className="text-2xl mb-2" aria-hidden="true">⏱️</div>
  // eslint-disable-next-line security/detect-object-injection
          <h2 id="session-warning-title" className="font-mono text-[var(--warn)] text-lg font-bold uppercase tracking-wider">
            Session Expiring
          </h2>
  // eslint-disable-next-line security/detect-object-injection
          <p className="text-[var(--muted)] text-sm mt-2">
            Your session will lock in{' '}
  // eslint-disable-next-line security/detect-object-injection
            <span className="text-[var(--warn)] font-bold">{secondsRemaining}s</span>
          </p>
        </div>

        <div className="flex gap-2">
          <Button variant="primary" onClick={onDismiss} className="flex-1">
            Stay Active
          </Button>
          <Button variant="secondary" onClick={onLockNow} className="flex-1">
            Lock Now
          </Button>
        </div>
      </div>
    </div>
  );
}
