import { useState, useCallback, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { useAuth } from '@/hooks/useAuth';

interface SessionLockScreenProps {
  onUnlock: (password: string) => boolean;
  requirePassword?: boolean;
}

export function SessionLockScreen({ onUnlock, requirePassword = true }: SessionLockScreenProps) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const { user, verifyUnlockPassword } = useAuth();

  useEffect(() => {
    if (requirePassword) {
      inputRef.current?.focus();
    }
  }, [requirePassword]);

  const handleUnlock = useCallback(() => {
    if (isVerifying) return;
    if (requirePassword && !password) return;
    setIsVerifying(true);
    setError('');
    try {
      if (!requirePassword) {
        onUnlock('');
        setPassword('');
        return;
      }
      if (verifyUnlockPassword(password)) {
        onUnlock(password);
        setPassword('');
      } else {
        setError('Incorrect password');
      }
    } finally {
      setIsVerifying(false);
    }
  }, [password, onUnlock, verifyUnlockPassword, isVerifying, requirePassword]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleUnlock();
  };

  return (
    <div className="fixed inset-0 z-[10000] bg flex items-center justify-center" role="dialog" aria-modal="true" aria-label="Session locked">
      <div className="w-full max-w-sm p-6 border border-line bg-panel animate-in fade-in zoom-in-95 duration-200">
        <div className="text-center mb-4">
          <div className="text-2xl mb-2" aria-hidden="true">🔒</div>
          <h2 id="session-lock-title" className="font-mono text-accent text-lg font-bold uppercase tracking-wider">
            Session Locked
          </h2>
          <p className="text-muted text-sm mt-1">
            {user?.name || 'User'} — {requirePassword ? 'Re-authenticate to continue' : 'Continue to resume this session'}
          </p>
        </div>

        {requirePassword && (
          <Input
            ref={inputRef}
            id="unlock-password"
            type="password"
            label="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={handleKeyDown}
            error={error}
            placeholder="Enter password"
            className="mb-3"
            aria-describedby={error ? 'unlock-error' : undefined}
            autoComplete="current-password"
            disabled={isVerifying}
          />
        )}

        <Button
          variant="primary"
          onClick={handleUnlock}
          className="w-full"
          disabled={(requirePassword && !password) || isVerifying}
          aria-busy={isVerifying}
        >
          {isVerifying ? 'Verifying...' : requirePassword ? 'Unlock' : 'Continue session'}
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
    <div className="fixed inset-0 z-[9999] bg-panel/80 flex items-center justify-center p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Session expiring warning" aria-live="assertive">
      <div className="w-full max-w-sm p-6 border border-warn bg-panel animate-in fade-in zoom-in-95 duration-200">
        <div className="text-center mb-4">
          <div className="text-2xl mb-2" aria-hidden="true">⏱️</div>
          <h2 id="session-warning-title" className="font-mono text-warn text-lg font-bold uppercase tracking-wider">
            Session Expiring
          </h2>
          <p className="text-muted text-sm mt-2">
            Your session will lock in{' '}
            <span className="text-warn font-bold tabular-nums">{secondsRemaining}s</span>
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
