import { useState, useEffect, useRef, useCallback } from 'react';

const TIMEOUT_MS = 15 * 60 * 1000;
const WARNING_MS = 2 * 60 * 1000;

interface SessionState {
  isLocked: boolean;
  showWarning: boolean;
  remainingMs: number;
  lastActivity: number;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useSessionTimeout(onTimeout?: () => void) {
  const [state, setState] = useState<SessionState>(() => ({
    isLocked: false,
    showWarning: false,
    remainingMs: TIMEOUT_MS,
    lastActivity: Date.now(),
  }));

  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const warningTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isLockedRef = useRef(false);
  
  useEffect(() => {
    isLockedRef.current = state.isLocked;
  }, [state.isLocked]);

  const resetTimer = useCallback(() => {
    setState(prev => ({
      ...prev,
      isLocked: false,
      showWarning: false,
      remainingMs: TIMEOUT_MS,
      lastActivity: Date.now(),
    }));

    if (warningTimerRef.current) clearTimeout(warningTimerRef.current);
    if (timeoutRef.current) clearTimeout(timeoutRef.current);

    warningTimerRef.current = setTimeout(() => {
      setState(prev => ({ ...prev, showWarning: true }));
    }, TIMEOUT_MS - WARNING_MS);

    timeoutRef.current = setTimeout(() => {
      setState(prev => ({ ...prev, isLocked: true, showWarning: false }));
      onTimeout?.();
    }, TIMEOUT_MS);
  }, [onTimeout]);

  useEffect(() => {
    const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click', 'keypress'];

    const handler = () => {
      if (!isLockedRef.current) {
        resetTimer();
      }
    };

    events.forEach(event => {
      window.addEventListener(event, handler, { passive: true });
    });

    // Defer the initial resetTimer call
    Promise.resolve().then(() => {
      resetTimer();
    });

    timerRef.current = setInterval(() => {
      if (!isLockedRef.current) {
        setState(prev => {
          const elapsed = Date.now() - prev.lastActivity;
          const remaining = Math.max(0, TIMEOUT_MS - elapsed);
          return { ...prev, remainingMs: remaining };
        });
      }
    }, 1000);

    return () => {
      events.forEach(event => {
        window.removeEventListener(event, handler);
      });
      if (timerRef.current) clearInterval(timerRef.current);
      if (warningTimerRef.current) clearTimeout(warningTimerRef.current);
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, [resetTimer]);

  const unlock = useCallback(() => {
    resetTimer();
  }, [resetTimer]);

  return {
    isLocked: state.isLocked,
    showWarning: state.showWarning,
    remainingMs: state.remainingMs,
    remainingMinutes: Math.floor(state.remainingMs / 60000),
    remainingSeconds: Math.floor((state.remainingMs % 60000) / 1000),
    unlock,
  };
}

export function SessionLockScreen({ onUnlock }: { onUnlock: () => void }) {
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = () => {
    if (pin.length >= 4) {
      onUnlock();
      setPin('');
      setError('');
    } else {
      setError('Enter at least 4 characters to unlock');
    }
  };

  return (
    <div className="session-lock-overlay" role="dialog" aria-modal="true" aria-label="Session locked">
      <div className="session-lock-card">
        <div className="lock-icon">🔒</div>
        <h2>Session Locked</h2>
        <p>Your session has been locked due to inactivity.</p>
        <div className="lock-input-group">
          <input
            type="password"
            className="form-input"
            placeholder="Enter password to unlock"
            value={pin}
            onChange={e => { setPin(e.target.value); setError(''); }}
            onKeyDown={e => { if (e.key === 'Enter') handleSubmit(); }}
            // eslint-disable-next-line jsx-a11y/no-autofocus
            autoFocus
            aria-label="Password to unlock session"
          />
          {error && <p className="lock-error" role="alert">{error}</p>}
          <button className="btn btn-primary" onClick={handleSubmit}>
            Unlock
          </button>
        </div>
      </div>
    </div>
  );
}

export function SessionTimeoutWarning({
  remainingMinutes,
  remainingSeconds,
  onStay,
}: {
  remainingMinutes: number;
  remainingSeconds: number;
  onStay: () => void;
}) {
  return (
    <div className="session-warning-overlay" role="alertdialog" aria-label="Session timeout warning">
      <div className="session-warning-card">
        <h3>⏰ Session Expiring Soon</h3>
        <p>
          Your session will lock in{' '}
          <strong>
            {remainingMinutes}:{remainingSeconds.toString().padStart(2, '0')}
          </strong>
        </p>
        <button className="btn btn-primary" onClick={onStay}>
          Stay Logged In
        </button>
      </div>
    </div>
  );
}
