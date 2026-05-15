export interface SessionConfig {
  timeoutMs: number;
  warningMs: number;
  onTimeout: () => void;
  onWarning?: () => void;
  onWarningDismiss?: () => void;
}

const SESSION_STORAGE_KEY = 'cyber-pipeline-session';

class SessionManager {
  private timeoutMs: number;
  private warningMs: number;
  private onTimeout: () => void;
  private onWarning?: () => void;
  private onWarningDismiss?: () => void;
  private lastActivity: number;
  private warningTimer: ReturnType<typeof setTimeout> | null = null;
  private timeoutTimer: ReturnType<typeof setTimeout> | null = null;
  private isLocked = false;
  private _warningShown = false;

  constructor(config: SessionConfig) {
    this.timeoutMs = config.timeoutMs;
    this.warningMs = config.warningMs;
    this.onTimeout = config.onTimeout;
    this.onWarning = config.onWarning;
    this.onWarningDismiss = config.onWarningDismiss;
    this.lastActivity = Date.now();
  }

  start(): void {
    this.bindEvents();
    this.resetTimers();
  }

  stop(): void {
    this.unbindEvents();
    this.clearTimers();
  }

  reset(): void {
    if (this.isLocked) return;
    this.lastActivity = Date.now();
    this._warningShown = false;
    this.resetTimers();
  }

  unlock(): void {
    this.isLocked = false;
    this.lastActivity = Date.now();
    this._warningShown = false;
    this.onWarningDismiss?.();
    this.resetTimers();
    localStorage.removeItem(`${SESSION_STORAGE_KEY}:locked`);
  }

  isSessionLocked(): boolean {
    return this.isLocked;
  }

  getTimeRemaining(): number {
    if (this.isLocked) return 0;
    const elapsed = Date.now() - this.lastActivity;
    return Math.max(0, this.timeoutMs - elapsed);
  }

  private bindEvents(): void {
    window.addEventListener('mousemove', this.handleActivity);
    window.addEventListener('mousedown', this.handleActivity);
    window.addEventListener('keydown', this.handleActivity);
    // FIX: Debounce scroll and touch events to reduce excessive handler calls
    window.addEventListener('scroll', this.handleActivity, { passive: true });
    window.addEventListener('touchstart', this.handleActivity, { passive: true });
    window.addEventListener('click', this.handleActivity);
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
  }

  private unbindEvents(): void {
    window.removeEventListener('mousemove', this.handleActivity);
    window.removeEventListener('mousedown', this.handleActivity);
    window.removeEventListener('keydown', this.handleActivity);
    window.removeEventListener('scroll', this.handleActivity);
    window.removeEventListener('touchstart', this.handleActivity);
    window.removeEventListener('click', this.handleActivity);
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
  }

  private activityDebounceTimer: ReturnType<typeof setTimeout> | null = null;

  private handleActivity = (): void => {
    if (this.activityDebounceTimer) return;
    
    this.reset();
    
    this.activityDebounceTimer = setTimeout(() => {
      this.activityDebounceTimer = null;
    }, 1000); // 1s debounce
  };

  private handleVisibilityChange = (): void => {
    if (document.visibilityState === 'visible') {
      this.reset();
    }
  };

  private resetTimers(): void {
    this.clearTimers();

    this.warningTimer = setTimeout(() => {
      if (!this.isLocked) {
        this._warningShown = true;
        this.onWarning?.();
      }
    }, this.warningMs);

    this.timeoutTimer = setTimeout(() => {
      this.lock();
    }, this.timeoutMs);
  }

  private clearTimers(): void {
    if (this.warningTimer) {
      clearTimeout(this.warningTimer);
      this.warningTimer = null;
    }
    if (this.timeoutTimer) {
      clearTimeout(this.timeoutTimer);
      this.timeoutTimer = null;
    }
  }

  private lock(): void {
    this.isLocked = true;
    this.clearTimers();
    localStorage.setItem(`${SESSION_STORAGE_KEY}:locked`, 'true');
    this.onTimeout();
  }

  dismissWarning(): void {
    this._warningShown = false;
    this.onWarningDismiss?.();
    this.resetTimers();
  }
}

let sessionManagerInstance: SessionManager | null = null;

export function createSessionManager(config: SessionConfig): SessionManager {
  // FIX: Stop old instance before creating new one to prevent leaked event listeners
  if (sessionManagerInstance) {
    sessionManagerInstance.stop();
  }
  sessionManagerInstance = new SessionManager(config);
  return sessionManagerInstance;
}

export function getSessionManager(): SessionManager | null {
  return sessionManagerInstance;
}

export function isSessionLocked(): boolean {
  return localStorage.getItem(`${SESSION_STORAGE_KEY}:locked`) === 'true';
}

// FIX: Renamed from useSessionTimeout since it's not a React hook
export function createSessionTimeout(
  timeoutMinutes = 15,
  onTimeout: () => void,
  onWarning?: () => void
) {
  const timeoutMs = timeoutMinutes * 60 * 1000;
  const warningMs = Math.max(timeoutMs - 60000, 0);

  return {
    start: () => {
      const manager = createSessionManager({
        timeoutMs,
        warningMs,
        onTimeout,
        onWarning,
      });
      manager.start();
      return manager;
    },
    timeoutMinutes,
    warningSeconds: Math.floor((timeoutMs - warningMs) / 1000),
  };
}
